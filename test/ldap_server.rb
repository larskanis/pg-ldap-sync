#!/usr/local/bin/ruby -w

# This is a trivial LDAP server which just stores directory entries in RAM.
# It does no validation or authentication. This is intended just to
# demonstrate the API, it's not for real-world use!!

require 'rubygems'
require 'ldap/server'

# We subclass the Operation class, overriding the methods to do what we need

class HashOperation < LDAP::Server::Operation
  def initialize(connection, messageID, hash)
    super(connection, messageID)
    @hash = hash   # an object reference to our directory data
  end

  def search(basedn, scope, deref, filter)
    basedn.downcase!

    case scope
    when LDAP::Server::BaseObject
      # client asked for single object by DN
      obj = @hash[basedn]
      raise LDAP::ResultError::NoSuchObject unless obj
      send_SearchResultEntry(basedn, obj) if LDAP::Server::Filter.run(filter, obj)

    when LDAP::Server::WholeSubtree
      @hash.each do |dn, av|
        next unless dn.index(basedn, -basedn.length)    # under basedn?
        next unless LDAP::Server::Filter.run(filter, av)  # attribute filter?
        send_SearchResultEntry(dn, av)
      end

    else
      raise LDAP::ResultError::UnwillingToPerform, "OneLevel not implemented"

    end
  end
end

