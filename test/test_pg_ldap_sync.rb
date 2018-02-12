require "minitest/autorun"
require 'minitest/hooks/test'
require "pg_ldap_sync"
require 'yaml'
require 'fileutils'
require_relative 'ldap_server'

class TestPgLdapSync < Minitest::Test
  include Minitest::Hooks

  def log_and_run( *cmd )
    puts cmd.join(' ')
    system( *cmd )
    raise "Command failed: [%s]" % [cmd.join(' ')] unless $?.success?
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
  end

  def stop_pg_server
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
    log_and_run 'psql', '-e', '-c', "DROP ROLE IF EXISTS fred, wilma, \"Flintstones\", \"Wilmas\", \"All Users\"", 'postgres'
  end

  def psqlre(*args)
    /^\s*#{args[0]}[ |]*#{args[1]}[ |\{"]*#{args[2..-1].join('[", ]+')}["\}\s]*$/
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
    PgLdapSync::Application.run(["-c", "test/fixtures/#{config}.yaml", "-vv"])
  end

  def sync_to_fixture(fixture: "ldapdb", config: "config-ldapdb")
    load_ldap_fixture(fixture)
    sync_with_config(config)
  end

  def sync_change
    sync_to_fixture

    yield(@directory)

    sync_with_config
    exec_psql_du
  end

  def test_base_users_groups_memberships
    psql_du = sync_change{}

    assert_match(psqlre('All Users','Cannot login'), psql_du)
    assert_match(psqlre('Flintstones','Cannot login'), psql_du)
    assert_match(psqlre('Wilmas','Cannot login','All Users'), psql_du)
    assert_match(psqlre('fred','','All Users','Flintstones'), psql_du)
    assert_match(psqlre('wilma','','Flintstones','Wilmas'), psql_du)
  end

  def test_add_membership
    psql_du = sync_change do |dir|
      # add 'Fred' to 'Wilmas'
      @directory[0]['cn=Wilmas,dc=example,dc=com']['member'] << 'cn=Fred Flintstone,dc=example,dc=com'
    end
    assert_match(psqlre('fred','','All Users','Flintstones', 'Wilmas'), psql_du)
  end

  def test_revoke_membership
    psql_du = sync_change do |dir|
      # revoke membership of 'wilma' to 'Flintstones'
      dir[0]['cn=Flintstones,dc=example,dc=com']['member'].pop
    end
    assert_match(psqlre('wilma','','Wilmas'), psql_du)
  end

  def test_rename_role
    psql_du = sync_change do |dir|
      # rename role 'wilma'
      dir[0]['cn=Wilma Flintstone,dc=example,dc=com']['sAMAccountName'] = ['Wilma Flintstone']
    end
    refute_match(/wilma/, psql_du)
    assert_match(psqlre('Wilma Flintstone','','Flintstones','Wilmas'), psql_du)
  end
end
