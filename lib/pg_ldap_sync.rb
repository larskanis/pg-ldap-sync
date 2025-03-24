require "pg_ldap_sync/application"
require "pg_ldap_sync/compat"
require "pg_ldap_sync/version"

module PgLdapSync
  class LdapError < RuntimeError
  end

  class ApplicationExit < RuntimeError
    attr_reader :exitcode

    def initialize(exitcode, error = nil)
      super(error)
      @exitcode = exitcode
    end
  end

  class InvalidConfig < ApplicationExit
  end

  class ErrorExit < ApplicationExit
  end
end
