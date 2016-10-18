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

  def start_ldap_server
    yaml_fname = File.join(File.dirname(__FILE__), "fixtures/ldapdb.yaml")
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
    log_and_run 'psql', '-e', '-c', "DROP ROLE IF EXISTS fred, wilma, betty, rubble, pebbles, kids, flintstone_kids, \"Flintstones\", \"Wilmas\", \"All Users\"", 'postgres'
  end

  def stop_pg_server
    log_and_run 'pg_ctl', '-w', '-o', "-k.", '-D', 'temp/pg_data', 'stop'
  end

  def setup
    start_ldap_server
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
      `psql -c \\du postgres`
    else
      `psql -c \\\\du postgres`
    end
    puts text
    return text
  end

  def test_sanity
    PgLdapSync::Application.run(%w[-c test/fixtures/config-ldapdb.yaml -vv])

    ENV['LC_MESSAGES'] = 'C'
    psql_du = exec_psql_du

    assert_match(psqlre('All Users','Cannot login'), psql_du)
    assert_match(psqlre('Flintstones','Cannot login'), psql_du)
    assert_match(psqlre('Wilmas','Cannot login','All Users'), psql_du)
    assert_match(psqlre('fred','','Flintstones','All Users'), psql_du)
    assert_match(psqlre('wilma','','Flintstones','Wilmas'), psql_du)
    assert_match(psqlre('betty', '', 'rubble'), psql_du)
    assert_match(psqlre('rubble', ''), psql_du)
    assert_match(psqlre('pebbles', '', 'kids', 'flintstone_kids'), psql_du)
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

    PgLdapSync::Application.run(%w[-c test/fixtures/config-ldapdb.yaml -vv])
    psql_du = exec_psql_du

    assert_match(psqlre('All Users','Cannot login'), psql_du)
    assert_match(psqlre('Flintstones','Cannot login'), psql_du)
    assert_match(psqlre('Wilmas','Cannot login','All Users'), psql_du)
    assert_match(psqlre('fred','','Flintstones','All Users'), psql_du)
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

    PgLdapSync::Application.run(%w[-c test/fixtures/config-ldapdb.yaml -vv])
    psql_du = exec_psql_du

    assert_match(psqlre('All Users','Cannot login'), psql_du)
    assert_match(psqlre('Flintstones','Cannot login'), psql_du)
    assert_match(psqlre('Wilmas','Cannot login','All Users'), psql_du)
    assert_match(psqlre('fred','','Flintstones','All Users'), psql_du)
    assert_no_match(/wilma/, psql_du)
    assert_match(psqlre('Wilma Flintstone','','Flintstones','Wilmas'), psql_du)
    assert_match(psqlre('pebbles', '', 'kids'), psql_du)
    assert_match(psqlre('bamm-bamm', '', 'rubble_kids'), psql_du)
    assert_match(psqlre('betty', '', 'rubble'), psql_du)
    assert_match(psqlre('rubble', ''), psql_du)
    assert_match(psqlre('rubble_kids', 'Cannot login'), psql_du)
    assert_match(psqlre('kids', ''), psql_du)
  end
end
