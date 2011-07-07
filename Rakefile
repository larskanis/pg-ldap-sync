# -*- ruby -*-

require 'rubygems'
require 'hoe'

Hoe.spec 'pg-ldap-sync' do
  developer('Lars Kanis', 'kanis@comcard.de')

  extra_deps << ['net-ldap', '>= 0.2']
  extra_deps << ['kwalify', '>= 0.7']
  extra_dev_deps << ['ruby-ldapserver', '>= 0.3']

  self.readme_file = 'README.rdoc'
  spec_extras[:rdoc_options] = ['--main', readme_file, "--charset=UTF-8"]
  self.extra_rdoc_files << self.readme_file
end

# vim: syntax=ruby
