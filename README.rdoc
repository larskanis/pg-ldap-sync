= Use LDAP permissions in PostgreSQL

* https://github.com/larskanis/pg-ldap-sync

== DESCRIPTION:

PostgreSQL offers different authentication methods, like LDAP, SSPI, GSSAPI or SSL.
For any method the user must already exist in the database, before
the authentication can be used. LDAP is often used to do a centralized
user and role management in an enterprise environment.

This program synchronizes users, groups and memberships from LDAP to
PostgreSQL.

== FEATURES/PROBLEMS:

* Use Active Directory as LDAP-Server
* Configurable per YAML config file

== SYNOPSIS:

  pg_ldap_sync -vv -t

== REQUIREMENTS:

* Installed Ruby and rubygems
* LDAP- and PostgreSQL-Server

== INSTALL:

Install Ruby and rubygems:
* http://rubyinstaller.org/ on Windows
* <tt>apt-get install ruby rubygems</tt> on Debian

Install pg-ldap-sync and a database driver for PostgreSQL:
* <tt>gem install pg-ldap-sync postgres-pr</tt>

Or install from Git:
  git clone https://github.com/larskanis/pg-ldap-sync.git
  cd pg-ldap-sync
  rake install_gem


== LICENSE:

(The MIT License)

Copyright (c) 2011 FIX

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
