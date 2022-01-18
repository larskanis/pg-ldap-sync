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

