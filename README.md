[![Build Status](https://app.travis-ci.com/larskanis/pg-ldap-sync.svg?branch=master)](https://app.travis-ci.com/larskanis/pg-ldap-sync) [![Build status](https://ci.appveyor.com/api/projects/status/09xn9q5p64jbxtka/branch/master?svg=true)](https://ci.appveyor.com/project/larskanis/pg-ldap-sync/branch/master)

# Sync users and groups from LDAP to PostgreSQL

* https://github.com/larskanis/pg-ldap-sync

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

* User+group creation, deletion and changes in memberships are synchronized from LDAP to PostgreSQL
* Nested groups/roles supported
* Configurable per YAML config file
* Can use Active Directory as LDAP-Server
* Set scope of considered users/groups on LDAP and PG side
* Test mode which doesn't do any changes to the DBMS
* Both LDAP and PG connections can be secured by SSL/TLS
* Password, NTLM and Kerberos authentication to LDAP server

## REQUIREMENTS:

* Ruby-2.0+
* LDAP-v3 server
* PostgreSQL-server v9.0+

## INSTALL:

pg-ldap-sync is included in Ubuntu-22.04 and Debian-11 and newer.
It can be installed by

```sh
sudo apt install ruby-pg-ldap-sync
```

### Install from source

Install Ruby:

* on Windows: https://rubyinstaller.org
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

It is recommended to avoid granting permissions to synchronized users on the PostgreSQL server, but to grant permissions to groups instead.
This is because `DROP USER` statements invoked when a user leaves otherwise fail due to depending objects.
`DROP GROUP` equally fails if there are depending objects, but groups are typically more stable and removed rarely.


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
