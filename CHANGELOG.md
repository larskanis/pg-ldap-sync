## 0.5.2 / 2025-09-01

* Replace `kwalify` by `json-schema` to remove hundreds of warnings about keyword arguments in modern Ruby. #51
* Allow ERb syntax in config file. #52
  This can be used to insert password from environment variable like so: `password: <%= ENV["PASSWORD"] %>`
* Update documentation.


## 0.5.1 / 2025-03-22

* Add dependent gems for compat with ruby-3.5
* Add predefined roles for compat with PostgreSQL-16 and 17


## 0.5.0 / 2023-08-24

* Add Kerberos and NTLM authentication support to LDAP connection
* Fix retrieval of groups with over 1500 users in Active Directory server. #45


## 0.4.0 / 2022-12-02

* Support groups with over 1500 users in Active Directory server. #32
* Retrieve only necessary attributes from LDAP server.
* Add error text to exception, so that it's visible even if nothing is logged.
* Fix compatibility with PostgreSQL-15
* Require ruby-2.3+


## 0.3.0 / 2022-01-18

* Add config option :bothcase_name .
  This adds both spellings "Fred_Flintstone" and "fred_flintstone" as PostgreSQL users/groups.
* Update gem dependencies
* Fix compatibility with PostgreSQL-14
* Require ruby-2.4+


## 0.2.0 / 2018-03-13

* Update gem dependencies
* Fix compatibility to pg-1.0 gem
* Add `pg_ldap_sync --version`
* Fix compatibility with PostgreSQL-10
* Don't abort on SQL errors, but print ERROR notice
* Run sync within a SQL transaction, so that no partial sync happens
* Lots of improvements to the test suite
* Run automated tests on Travis-CI and Appveyor
* Remove support for postgres-pr, since it's no longer maintained


## 0.1.1 / 2012-11-15

* Add ability to lowercase the LDAP name for use as PG role name


## 0.1.0 / 2011-07-13

* Birthday!

