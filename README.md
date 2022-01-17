[![Build Status](https://app.travis-ci.com/larskanis/pg-ldap-sync.svg?branch=master)](https://app.travis-ci.com/larskanis/pg-ldap-sync) [![Build status](https://ci.appveyor.com/api/projects/status/09xn9q5p64jbxtka/branch/master?svg=true)](https://ci.appveyor.com/project/larskanis/pg-ldap-sync/branch/master)

# Use LDAP permissions in PostgreSQL

* http://github.com/larskanis/pg-ldap-sync

## DESCRIPTION:

LDAP is often used for a centralized user and role management in an enterprise environment.
PostgreSQL offers different authentication methods, like LDAP, SSPI, GSSAPI or SSL.
However, for any method the user must already exist in the database, before the authentication can be used.
There is currently no direct authorization of database users on LDAP.
So roles and memberships has to be administered twice.

This program helps to solve the issue by synchronizing users, groups and their memberships from LDAP to PostgreSQL.
Access to LDAP is used read-only.
`pg_ldap_sync` issues proper CREATE ROLE, DROP ROLE, GRANT and REVOKE commands to synchronize users and groups.

It is meant to be started as a cron job.

## FEATURES:

* Configurable per YAML config file
* Can use Active Directory as LDAP-Server
* Nested groups/roles supported
* Set scope of considered users/groups on LDAP and PG side
* Test mode which doesn't do any changes to the DBMS
* Both LDAP and PG connections can be secured by SSL/TLS

## REQUIREMENTS:

* Ruby-2.0+, JRuby-1.2+
* LDAP-v3 server
* PostgreSQL-server v9.0+

## INSTALL:

Install Ruby:

* on Windows: http://rubyinstaller.org
* on Debian/Ubuntu: `apt-get install ruby libpq-dev`

Install pg-ldap-sync and required dependencies:
```sh
  gem install pg-ldap-sync
```

### Install from Git:
```sh
  git clone https://github.com/larskanis/pg-ldap-sync.git
  cd pg-ldap-sync
  gem install bundler
  bundle install
  bundle exec rake install
```

## USAGE:

Create a config file based on
[config/sample-config.yaml](https://github.com/larskanis/pg-ldap-sync/blob/master/config/sample-config.yaml)
or even better
[config/sample-config2.yaml](https://github.com/larskanis/pg-ldap-sync/blob/master/config/sample-config2.yaml)

Run in test-mode:
```sh
  pg_ldap_sync -c my_config.yaml -vv -t
```
Run in modify-mode:
```sh
  pg_ldap_sync -c my_config.yaml -vv
```

## TEST:
There is a small test suite in the `test` directory that runs against an internal LDAP server and a PostgreSQL server. Ensure `pg_ctl`, `initdb` and `psql` commands are in the `PATH` like so:
```sh
  cd pg-ldap-sync
  bundle install
  PATH=$PATH:/usr/lib/postgresql/10/bin/ bundle exec rake test
```

## ISSUES:

* There is currently no way to set certain user attributes in PG based on individual attributes in LDAP (expiration date etc.)


## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
