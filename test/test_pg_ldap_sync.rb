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
    unless File.exist?('temp/pg_data')
      FileUtils.mkdir_p 'temp/pg_data'
      log_and_run 'initdb', '-D', 'temp/pg_data'
    end
    log_and_run 'pg_ctl', '-w', '-o', "-k.", '-D', 'temp/pg_data', 'start'
    log_and_run 'psql', '-e', '-c', "DROP ROLE IF EXISTS fred, wilma, \"Flintstones\", \"Wilmas\", \"All Users\"", 'postgres'
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

  def test_sanity
    PgLdapSync::Application.run(%w[-c test/fixtures/config-ldapdb.yaml -vv])

    ENV['LC_MESSAGES'] = 'C'
    psql_du = `psql -c \\\\du postgres`
    puts psql_du
    
    assert_match(psqlre('All Users','Cannot login'), psql_du)
    assert_match(psqlre('Flintstones','Cannot login'), psql_du)
    assert_match(psqlre('Wilmas','Cannot login','All Users'), psql_du)
    assert_match(psqlre('fred','','All Users','Flintstones'), psql_du)
    assert_match(psqlre('wilma','','Flintstones','Wilmas'), psql_du)
    
    @directory['cn=Flintstones,dc=example,dc=com']['member'].pop
    
    PgLdapSync::Application.run(%w[-c test/fixtures/config-ldapdb.yaml -vv])
    psql_du = `psql -c \\\\du postgres`
    puts psql_du
    
    assert_match(psqlre('All Users','Cannot login'), psql_du)
    assert_match(psqlre('Flintstones','Cannot login'), psql_du)
    assert_match(psqlre('Wilmas','Cannot login','All Users'), psql_du)
    assert_match(psqlre('fred','','All Users','Flintstones'), psql_du)
    assert_match(psqlre('wilma','','Wilmas'), psql_du)
  end
end
