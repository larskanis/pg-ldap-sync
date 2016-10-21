#!/usr/bin/env ruby

require "test/unit"
require "pg_ldap_sync/application"
require 'yaml'
require 'test/ldap_server'
require 'fileutils'

class TestPgLdapSync < Test::Unit::TestCase
  def log_and_run( *cmd )
    puts cmd.join(' ')
    system( *cmd )
    raise "Command failed: [%s]" % [cmd.join(' ')] unless $?.success?
  end

  def start_ldap_server(file_name)
    yaml_fname = File.join(File.dirname(__FILE__), file_name)
    @directory = File.open(yaml_fname){|f| YAML::load(f.read) }

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
      :operation_args   => [@directory]
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
    log_and_run 'psql', '-e', '-c', "DROP ROLE IF EXISTS fred, \"bamm-bamm\", rubble_kids, wilma, \"Wilma Flintstone\", betty, rubble, pebbles, kids, flintstone_kids, \"Flintstones\", \"Wilmas\", \"All Users\", ldap_users, ldap_groups", 'postgres'
  end

  def stop_pg_server
    log_and_run 'pg_ctl', '-w', '-o', "-k.", '-D', 'temp/pg_data', 'stop'
  end

  def setup
    start_pg_server
  end

  def teardown
    stop_ldap_server
    stop_pg_server
  end

  def psqlre(*args)
    /^\s*#{args[0]}[ |]*#{args[1]}[ |\{"]*#{args[2..-1].join('[", ]+')}["\}\s]*$/
  end
  
  def exec_psql_du
    text = if RUBY_PLATFORM=~/mingw|mswin/
      `psql -d postgres -c "SELECT r.rolname AS \\"Role name\\", CASE WHEN r.rolcanlogin THEN '' ELSE 'Cannot login' END AS \\"Attributes\\", ARRAY(SELECT b.rolname FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles b ON (m.roleid = b.oid) WHERE m.member = r.oid ORDER BY lower(b.rolname) ASC) AS \\"Member of\\" FROM pg_catalog.pg_roles r ORDER BY 1;"`
    else
      `psql -d postgres -c "SELECT r.rolname AS \\\"Role name\\\\", CASE WHEN r.rolcanlogin THEN '' ELSE 'Cannot login' END AS \\\"Attributes\\\", ARRAY(SELECT b.rolname FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles b ON (m.roleid = b.oid) WHERE m.member = r.oid ORDER BY lower(b.rolname) ASC) AS \\\"Member of\\\" FROM pg_catalog.pg_roles r ORDER BY 1;"`
    end
    puts text
    return text
  end

#=begin
  def test_sanity1
    start_ldap_server("fixtures/ldapdb.yaml")

    PgLdapSync::Application.run(%w[-c test/fixtures/config-ldapdb.yaml -vv])

    ENV['LC_MESSAGES'] = 'C'
    psql_du = exec_psql_du

    assert_match(psqlre('All Users','Cannot login'), psql_du)
    assert_match(psqlre('Flintstones','Cannot login'), psql_du)
    assert_match(psqlre('Wilmas','Cannot login','All Users'), psql_du)
    assert_match(psqlre('fred','','All Users','Flintstones'), psql_du)
    assert_match(psqlre('wilma','','Flintstones','Wilmas'), psql_du)

    # revoke membership of 'wilma' to 'Flintstones'
    @directory['cn=Flintstones,dc=example,dc=com']['member'].pop

    PgLdapSync::Application.run(%w[-c test/fixtures/config-ldapdb.yaml -vv])
    psql_du = exec_psql_du

    assert_match(psqlre('All Users','Cannot login'), psql_du)
    assert_match(psqlre('Flintstones','Cannot login'), psql_du)
    assert_match(psqlre('Wilmas','Cannot login','All Users'), psql_du)
    assert_match(psqlre('fred','','All Users','Flintstones'), psql_du)
    assert_match(psqlre('wilma','','Wilmas'), psql_du)

    # rename role 'wilma'
    @directory['cn=Wilma Flintstone,dc=example,dc=com']['sAMAccountName'] = ['Wilma Flintstone']
    # re-add 'Wilma' to 'Flintstones'
    @directory['cn=Flintstones,dc=example,dc=com']['member'] << 'cn=Wilma Flintstone,dc=example,dc=com'

    PgLdapSync::Application.run(%w[-c test/fixtures/config-ldapdb.yaml -vv])
    psql_du = exec_psql_du

    assert_match(psqlre('All Users','Cannot login'), psql_du)
    assert_match(psqlre('Flintstones','Cannot login'), psql_du)
    assert_match(psqlre('Wilmas','Cannot login','All Users'), psql_du)
    assert_match(psqlre('fred','','All Users','Flintstones'), psql_du)
    assert_no_match(/wilma/, psql_du)
    assert_match(psqlre('Wilma Flintstone','','Flintstones','Wilmas'), psql_du)
  end
#=end

#=begin
  def test_sanity2
    start_ldap_server("fixtures/ldapdb.yaml")

    PgLdapSync::Application.run(%w[-c test/fixtures/config-ldapdb2.yaml -vv])

    ENV['LC_MESSAGES'] = 'C'
    psql_du = exec_psql_du

    assert_match(psqlre('All Users','Cannot login','ldap_groups'), psql_du)
    assert_match(psqlre('Flintstones','Cannot login','ldap_groups'), psql_du)
    assert_match(psqlre('Wilmas','Cannot login','All Users','ldap_groups'), psql_du)
    assert_match(psqlre('fred','','All Users','Flintstones','ldap_users'), psql_du)
    assert_match(psqlre('wilma','','Flintstones','ldap_users','Wilmas'), psql_du)

    # revoke membership of 'wilma' to 'Flintstones'
    @directory['cn=Flintstones,dc=example,dc=com']['member'].pop

    PgLdapSync::Application.run(%w[-c test/fixtures/config-ldapdb2.yaml -vv])
    psql_du = exec_psql_du

    assert_match(psqlre('All Users','Cannot login','ldap_groups'), psql_du)
    assert_match(psqlre('Flintstones','Cannot login','ldap_groups'), psql_du)
    assert_match(psqlre('Wilmas','Cannot login','All Users','ldap_groups'), psql_du)
    assert_match(psqlre('fred','','All Users','Flintstones','ldap_users'), psql_du)
    assert_match(psqlre('wilma','','ldap_users','Wilmas'), psql_du)

    # rename role 'wilma'
    @directory['cn=Wilma Flintstone,dc=example,dc=com']['sAMAccountName'] = ['Wilma Flintstone']
    # re-add 'Wilma' to 'Flintstones'
    @directory['cn=Flintstones,dc=example,dc=com']['member'] << 'cn=Wilma Flintstone,dc=example,dc=com'

    PgLdapSync::Application.run(%w[-c test/fixtures/config-ldapdb2.yaml -vv])
    psql_du = exec_psql_du

    assert_match(psqlre('All Users','Cannot login','ldap_groups'), psql_du)
    assert_match(psqlre('Flintstones','Cannot login','ldap_groups'), psql_du)
    assert_match(psqlre('Wilmas','Cannot login','All Users','ldap_groups'), psql_du)
    assert_match(psqlre('fred','','All Users','Flintstones','ldap_users'), psql_du)
    assert_no_match(/wilma/, psql_du)
    assert_match(psqlre('Wilma Flintstone','','Flintstones','ldap_users','Wilmas'), psql_du)
  end
#=end

#=begin
  def test_sanity3
    start_ldap_server("fixtures/ldapdb3.yaml")

    PgLdapSync::Application.run(%w[-c test/fixtures/config-ldapdb3.yaml -vv])

    ENV['LC_MESSAGES'] = 'C'
    psql_du = exec_psql_du

    assert_match(psqlre('All Users','Cannot login'), psql_du)
    assert_match(psqlre('Flintstones','Cannot login'), psql_du)
    assert_match(psqlre('Wilmas','Cannot login','All Users'), psql_du)
    assert_match(psqlre('fred','','All Users','Flintstones'), psql_du)
    assert_match(psqlre('wilma','','Flintstones','Wilmas'), psql_du)
    assert_match(psqlre('betty', '', 'rubble'), psql_du)
    assert_match(psqlre('rubble', ''), psql_du)
    assert_match(psqlre('pebbles', '', 'flintstone_kids', 'kids'), psql_du)
    assert_match(psqlre('kids', ''), psql_du)
    assert_match(psqlre('bamm-bamm', '', 'rubble_kids'), psql_du)
    assert_match(psqlre('rubble_kids','Cannot login'), psql_du)
    assert_match(psqlre('flintstone_kids',''), psql_du)

    # revoke membership of 'wilma' to 'Flintstones'
    @directory['cn=flintstones,ou=groups,dc=example,dc=com']['member'].pop
    # remove user 'rubble'
    @directory.delete('cn=rubble,dc=example,dc=com')
    # reove user and group 'flintstone_kids'
    @directory.delete('cn=flintstone_kids,ou=groups,dc=example,dc=com')
    @directory.delete('cn=flintstone_kids,dc=example,dc=com')
    # remove group 'kids'
    @directory.delete('cn=kids,ou=groups,dc=example,dc=com')
    # remove group 'rubble_kids'
    @directory.delete('cn=rubble_kids,ou=groups,dc=example,dc=com')
    # add user 'rubble_kids'
    @directory['cn=rubble_kids,dc=example,dc=com'] = {'cn' => ['rubble_kids'], 'mail'=>['rubble_kids@bedrock.org'], 'sn'=>['rubble_kids'], 'sAMAccountName'=>['rubble_kids']}

    PgLdapSync::Application.run(%w[-c test/fixtures/config-ldapdb3.yaml -vv])
    psql_du = exec_psql_du

    assert_match(psqlre('All Users','Cannot login'), psql_du)
    assert_match(psqlre('Flintstones','Cannot login'), psql_du)
    assert_match(psqlre('Wilmas','Cannot login','All Users'), psql_du)
    assert_match(psqlre('fred','','All Users','Flintstones'), psql_du)
    assert_match(psqlre('wilma','','Wilmas'), psql_du)
    assert_match(psqlre('betty', '', 'rubble'), psql_du)
    assert_match(psqlre('rubble', 'Cannot login'), psql_du)
    assert_match(psqlre('pebbles', ''), psql_du)
    assert_match(psqlre('kids', ''), psql_du)
    assert_no_match(/flintstone_kids/, psql_du)
    assert_match(psqlre('bamm-bamm', ''), psql_du)
    assert_match(psqlre('rubble_kids', ''), psql_du)

    # rename role 'wilma'
    @directory['cn=Wilma Flintstone,dc=example,dc=com']['sAMAccountName'] = ['Wilma Flintstone']
    # re-add 'Wilma' to 'Flintstones'
    @directory['cn=flintstones,ou=groups,dc=example,dc=com']['member'] << 'cn=Wilma Flintstone,dc=example,dc=com'
    #Recreate User 'rubble'
    @directory['cn=rubble,dc=example,dc=com'] = {'cn' => ['rubble'], 'mail'=>['rubble@bedrock.org'], 'sn'=>['rubble'], 'sAMAccountName'=>['rubble']}
    #Recreate Group 'kids'
    @directory['cn=kids,ou=groups,dc=example,dc=com'] = {'cn' => ['kids'], 'member'=>['cn=Pebbles Flintstone,dc=example,dc=com']}
    # remove user 'rubble_kids'
    @directory.delete('cn=rubble_kids,dc=example,dc=com')
    #Recreate Group 'rubble_kids'
    @directory['cn=rubble_kids,ou=groups,dc=example,dc=com'] = {'cn' => ['rubble_kids'], 'member'=>['cn=Bamm-Bamm Rubble,dc=example,dc=com']}

    PgLdapSync::Application.run(%w[-c test/fixtures/config-ldapdb3.yaml -vv])
    psql_du = exec_psql_du

    assert_match(psqlre('All Users','Cannot login'), psql_du)
    assert_match(psqlre('Flintstones','Cannot login'), psql_du)
    assert_match(psqlre('Wilmas','Cannot login','All Users'), psql_du)
    assert_match(psqlre('fred','','All Users','Flintstones'), psql_du)
    assert_no_match(/wilma/, psql_du)
    assert_match(psqlre('Wilma Flintstone','','Flintstones','Wilmas'), psql_du)
    assert_match(psqlre('pebbles', '', 'kids'), psql_du)
    assert_match(psqlre('bamm-bamm', '', 'rubble_kids'), psql_du)
    assert_match(psqlre('betty', '', 'rubble'), psql_du)
    assert_match(psqlre('rubble', ''), psql_du)
    assert_match(psqlre('rubble_kids', 'Cannot login'), psql_du)
    assert_match(psqlre('kids', ''), psql_du)
  end
#=end

#=begin
  def test_sanity4
    start_ldap_server("fixtures/ldapdb3.yaml")

    PgLdapSync::Application.run(%w[-c test/fixtures/config-ldapdb4.yaml -vv])

    ENV['LC_MESSAGES'] = 'C'
    psql_du = exec_psql_du

    assert_match(psqlre('All Users','Cannot login','ldap_groups'), psql_du)
    assert_match(psqlre('Flintstones','Cannot login','ldap_groups'), psql_du)
    assert_match(psqlre('Wilmas','Cannot login','All Users','ldap_groups'), psql_du)
    assert_match(psqlre('fred','','All Users','Flintstones','ldap_users'), psql_du)
    assert_match(psqlre('wilma','','Flintstones','ldap_users','Wilmas'), psql_du)
    assert_match(psqlre('betty', '','ldap_users', 'rubble'), psql_du)
    assert_match(psqlre('rubble', '','ldap_groups','ldap_users'), psql_du)
    assert_match(psqlre('pebbles', '', 'flintstone_kids', 'kids','ldap_users'), psql_du)
    assert_match(psqlre('kids', '','ldap_groups','ldap_users'), psql_du)
    assert_match(psqlre('bamm-bamm', '','ldap_users', 'rubble_kids'), psql_du)
    assert_match(psqlre('rubble_kids','Cannot login','ldap_groups'), psql_du)
    assert_match(psqlre('flintstone_kids','','ldap_groups','ldap_users'), psql_du)

    # revoke membership of 'wilma' to 'Flintstones'
    @directory['cn=flintstones,ou=groups,dc=example,dc=com']['member'].pop
    # remove user 'rubble'
    @directory.delete('cn=rubble,dc=example,dc=com')
    # reove user and group 'flintstone_kids'
    @directory.delete('cn=flintstone_kids,ou=groups,dc=example,dc=com')
    @directory.delete('cn=flintstone_kids,dc=example,dc=com')
    # remove group 'kids'
    @directory.delete('cn=kids,ou=groups,dc=example,dc=com')
    # remove group 'rubble_kids'
    @directory.delete('cn=rubble_kids,ou=groups,dc=example,dc=com')
    # add user 'rubble_kids'
    @directory['cn=rubble_kids,dc=example,dc=com'] = {'cn' => ['rubble_kids'], 'mail'=>['rubble_kids@bedrock.org'], 'sn'=>['rubble_kids'], 'sAMAccountName'=>['rubble_kids']}

    PgLdapSync::Application.run(%w[-c test/fixtures/config-ldapdb4.yaml -vv])
    psql_du = exec_psql_du

    assert_match(psqlre('All Users','Cannot login', 'ldap_groups'), psql_du)
    assert_match(psqlre('Flintstones','Cannot login', 'ldap_groups'), psql_du)
    assert_match(psqlre('Wilmas','Cannot login','All Users', 'ldap_groups'), psql_du)
    assert_match(psqlre('fred','','All Users','Flintstones', 'ldap_users'), psql_du)
    assert_match(psqlre('wilma','','ldap_users','Wilmas'), psql_du)
    assert_match(psqlre('betty', '','ldap_users', 'rubble'), psql_du)
    assert_match(psqlre('rubble', 'Cannot login','ldap_groups'), psql_du)
    assert_match(psqlre('pebbles', '','ldap_users'), psql_du)
    assert_match(psqlre('kids', '','ldap_users'), psql_du)
    assert_no_match(/flintstone_kids/, psql_du)
    assert_match(psqlre('bamm-bamm', '','ldap_users'), psql_du)
    assert_match(psqlre('rubble_kids', '','ldap_users'), psql_du)

    # rename role 'wilma'
    @directory['cn=Wilma Flintstone,dc=example,dc=com']['sAMAccountName'] = ['Wilma Flintstone']
    # re-add 'Wilma' to 'Flintstones'
    @directory['cn=flintstones,ou=groups,dc=example,dc=com']['member'] << 'cn=Wilma Flintstone,dc=example,dc=com'
    #Recreate User 'rubble'
    @directory['cn=rubble,dc=example,dc=com'] = {'cn' => ['rubble'], 'mail'=>['rubble@bedrock.org'], 'sn'=>['rubble'], 'sAMAccountName'=>['rubble']}
    #Recreate Group 'kids'
    @directory['cn=kids,ou=groups,dc=example,dc=com'] = {'cn' => ['kids'], 'member'=>['cn=Pebbles Flintstone,dc=example,dc=com']}
    # remove user 'rubble_kids'
    @directory.delete('cn=rubble_kids,dc=example,dc=com')
    #Recreate Group 'rubble_kids'
    @directory['cn=rubble_kids,ou=groups,dc=example,dc=com'] = {'cn' => ['rubble_kids'], 'member'=>['cn=Bamm-Bamm Rubble,dc=example,dc=com']}

    PgLdapSync::Application.run(%w[-c test/fixtures/config-ldapdb4.yaml -vv])
    psql_du = exec_psql_du

    assert_match(psqlre('All Users','Cannot login','ldap_groups'), psql_du)
    assert_match(psqlre('Flintstones','Cannot login','ldap_groups'), psql_du)
    assert_match(psqlre('Wilmas','Cannot login','All Users','ldap_groups'), psql_du)
    assert_match(psqlre('fred','','All Users','Flintstones','ldap_users'), psql_du)
    assert_no_match(/wilma/, psql_du)
    assert_match(psqlre('Wilma Flintstone','','Flintstones','ldap_users','Wilmas'), psql_du)
    assert_match(psqlre('pebbles', '', 'kids','ldap_users'), psql_du)
    assert_match(psqlre('bamm-bamm', '', 'ldap_users','rubble_kids'), psql_du)
    assert_match(psqlre('betty', '', 'ldap_users','rubble'), psql_du)
    assert_match(psqlre('rubble', '','ldap_groups','ldap_users'), psql_du)
    assert_match(psqlre('rubble_kids', 'Cannot login', 'ldap_groups'), psql_du)
    assert_match(psqlre('kids', '','ldap_groups','ldap_users'), psql_du)
  end
#=end
end
