require "minitest/autorun"
require 'minitest/hooks/test'
require "pg_ldap_sync"
require 'yaml'
require 'fileutils'
require_relative 'ldap_server'

class TestPgLdapSync < Minitest::Test
  include Minitest::Hooks

  @@logid = 0

  def log_and_run( *cmd )
    if $DEBUG
      puts cmd.join(' ')
      system( *cmd )
      raise "Command failed: [%s]" % [cmd.join(' ')] unless $?.success?
    else
      fname = "temp/run_#{@@logid+=1}.log"
      pid = Process.spawn( *cmd, [:out, :err] => [fname, "w"] )
      Process.wait(pid)
      unless $?.success?
        $stderr.puts "Command failed: [%s]\n%s" % [cmd.join(' '), File.read(fname)]
      end
      File.unlink fname rescue nil # File is locked on Windows
      raise "Command failed: [%s]" % [cmd.join(' ')] unless $?.success?
    end
  end

  def start_ldap_server
    @directory = [{}]

    # Listen for incoming LDAP connections. For each one, create a Connection
    # object, which will invoke a HashOperation object for each request.

    @ldap_server = LDAP::Server.new(
      :port     => 1389,
      :nodelay    => true,
      :listen     => 10,
    # :ssl_key_file   => "key.pem",
    # :ssl_cert_file    => "cert.pem",
    # :ssl_on_connect   => true,
      :operation_class  => HashOperation,
      :operation_args   => @directory
    )
    @ldap_server.run_tcpserver
  end

  def stop_ldap_server
    @ldap_server.stop
  end

  def start_pg_server
    @port = 54321
    ENV['PGPORT'] = @port.to_s
    ENV['PGHOST'] = 'localhost'
    unless File.exist?('temp/pg_data/PG_VERSION')
      FileUtils.mkdir_p 'temp/pg_data'
      log_and_run 'initdb', '-D', 'temp/pg_data', '--no-locale'
    end
    log_and_run 'pg_ctl', '-w', '-o', "-k.", '-D', 'temp/pg_data', 'start'

    @pgconn = PG.connect dbname: 'postgres'
    @pgconn.exec "SET client_min_messages to warning"
  end

  def stop_pg_server
    @pgconn.close if @pgconn
    log_and_run 'pg_ctl', '-w', '-o', "-k.", '-D', 'temp/pg_data', 'stop'
  end

  def before_all
    super
    ENV['LC_MESSAGES'] = 'C'
    start_ldap_server
    start_pg_server
  end

  def after_all
    super
    stop_ldap_server
    stop_pg_server
  end

  def setup
    @pgconn.exec "DROP ROLE IF EXISTS \"Fred\", fred, \"Wilma\", wilma, \"Flintstones\", \"flintstones\", \"Wilmas\", \"wilmas\", \"All Users\", double_user"
  end

  def assert_role(role_name, attrs, member_of=[])
    res = @pgconn.exec("SELECT * FROM pg_roles WHERE rolname = '#{@pgconn.escape_string(role_name)}'")
    assert_equal 1, res.ntuples, "Role #{role_name} not found"

    res2 = @pgconn.exec "SELECT pr.rolname FROM pg_auth_members pam JOIN pg_roles pr ON pr.oid=pam.roleid WHERE pam.member=#{res.to_a[0]['oid']}"
    rolnames = res2.map{|t| t['rolname'] }
    assert_equal member_of.sort, rolnames.sort

    exp_attrs = []
    exp_attrs << 'Cannot login' if res[0]['rolcanlogin'] != 't'
    exp_attrs << 'Superuser' if res[0]['rolsuper'] == 't'

    assert_equal attrs, exp_attrs.join(", ")
  end

  def refute_role(role_name)
    res = @pgconn.exec("SELECT oid FROM pg_roles WHERE rolname = '#{@pgconn.escape_string(role_name)}'")
    assert_equal 0, res.ntuples, "Role #{role_name} not found"
  end

  def exec_psql_du
    text = if RUBY_PLATFORM=~/mingw|mswin/
      `psql -c \\du postgres`
    else
      `psql -c \\\\du postgres`
    end
    puts text
    return text
  end

  def load_ldap_fixture(fname)
    yaml_fname = File.join(File.dirname(__FILE__), "fixtures/#{fname}.yaml")
    @directory[0] = File.open(yaml_fname){|f| YAML::load(f.read) }
  end

  def sync_with_config(config="config-ldapdb")
    PgLdapSync::Application.run(["-c", "test/fixtures/#{config}.yaml"] + ($DEBUG ? ["-vv"] : ["--no-verbose"]))
  end

  def sync_to_fixture(fixture: "ldapdb", config: "config-ldapdb")
    load_ldap_fixture(fixture)
    sync_with_config(config)
  end

  def sync_change(fixture: "ldapdb", config: "config-ldapdb")
    sync_to_fixture(fixture: fixture, config: config)

    yield(@directory)

    sync_with_config(config)
    exec_psql_du if $DEBUG
  end

  def test_invalid_config
    assert_output(/key 'ldap_users:' is required/) do
      assert_raises(PgLdapSync::InvalidConfig) do
        sync_with_config("config-invalid")
      end
    end
  end

  def test_base_users_groups_memberships
    sync_change{}

    assert_role('All Users', 'Cannot login')
    assert_role('Flintstones', 'Cannot login')
    assert_role('Wilmas', 'Cannot login', ['All Users'])
    assert_role('Fred', '', ['All Users', 'Flintstones'])
    assert_role('Wilma', '', ['Flintstones', 'Wilmas'])
  end

  def test_add_membership
    sync_change do |dir|
      # add 'Fred' to 'Wilmas'
      @directory[0]['cn=Wilmas,dc=example,dc=com']['member'] << 'cn=Fred Flintstone,dc=example,dc=com'
    end
    refute_role('fred')
    assert_role('Fred', '', ['All Users', 'Flintstones', 'Wilmas'])
  end

  def test_add_membership_bothcase
    sync_change(config: "config-ldapdb-bothcase") do |dir|
      # add 'Fred' to 'Wilmas'
      @directory[0]['cn=Wilmas,dc=example,dc=com']['member'] << 'cn=Fred Flintstone,dc=example,dc=com'
    end
    assert_role('fred', '', ['All Users', 'all users', 'Flintstones', 'flintstones', 'Wilmas', 'wilmas'])
    assert_role('Fred', '', ['All Users', 'all users', 'Flintstones', 'flintstones', 'Wilmas', 'wilmas'])
  end

  def test_revoke_membership
    sync_change do |dir|
      # revoke membership of 'wilma' to 'Flintstones'
      dir[0]['cn=Flintstones,dc=example,dc=com']['member'].pop
    end
    assert_role('Wilma', '', ['Wilmas'])
  end

  def test_rename_role
    sync_change do |dir|
      # rename role 'wilma'
      dir[0]['cn=Wilma Flintstone,dc=example,dc=com']['sAMAccountName'] = ['Wilma Flintstone']
    end
    refute_role('wilma')
    refute_role('Wilma')
    assert_role('Wilma Flintstone', '', ['Flintstones', 'Wilmas'])
  end

  def test_dont_stop_on_error
    log_and_run 'psql', '-e', '-c', "CREATE ROLE double_user LOGIN", 'postgres'

    assert_raises(PgLdapSync::ErrorExit) do
      sync_change do |dir|
        dir[0]['cn=double_user,dc=example,dc=com'] = {'sAMAccountName' => 'double_user'}
      end
    end
  end
end
