#!/usr/bin/env ruby

require "net/ldap"
require "optparse"
require "erb"
require "yaml"
require "json-schema"
require "pg"
require "pg_ldap_sync/logger"

module PgLdapSync
  class Application
    attr_accessor :config_fname
    attr_accessor :log
    attr_accessor :test

    def string_to_symbol(hash)
      if hash.is_a?(Hash)
        hash.each_with_object({}) do |v, h|
          raise "expected String instead of #{h.inspect}" unless v[0].is_a?(String)
          h[v[0].intern] = string_to_symbol(v[1])
        end
      else
        hash
      end
    end

    def validate_config(config, schema, fname)
      schema = YAML.load_file(schema)
      errors = JSON::Validator.fully_validate(schema, config, validate_schema: true, insert_defaults: true)
      if errors && !errors.empty?
        errors.each do |err|
          log.fatal "error in #{fname}: #{err}"
        end
        raise InvalidConfig, 78 # EX_CONFIG
      end
    end

    def read_config_file(fname)
      raise "Config file #{fname.inspect} does not exist" unless File.exist?(fname)
      config = YAML.load(ERB.new(File.read(fname)).result)

      schema_fname = File.join(File.dirname(__FILE__), "../../config/schema.yaml")
      validate_config(config, schema_fname, fname)

      @config = string_to_symbol(config)
    end

    LdapRole = Struct.new :name, :dn, :member_dns

    def search_ldap_users
      ldap_user_conf = @config[:ldap_users]
      name_attribute = ldap_user_conf[:name_attribute]

      users = []
      res = @ldap.search(
        base: ldap_user_conf[:base],
        filter: ldap_user_conf[:filter],
        attributes: [name_attribute, :dn]
      ) do |entry|
        name = entry[name_attribute].first

        unless name
          log.warn "user attribute #{name_attribute.inspect} not defined for #{entry.dn}"
          next
        end
        log.info "found user-dn: #{entry.dn}"

        names = if ldap_user_conf[:bothcase_name]
          [name, name.downcase].uniq
        elsif ldap_user_conf[:lowercase_name]
          [name.downcase]
        else
          [name]
        end

        names.each do |n|
          users << LdapRole.new(n, entry.dn)
        end
        entry.each do |attribute, values|
          log.debug "   #{attribute}:"
          values.each do |value|
            log.debug "      --->#{value.inspect}"
          end
        end
      end
      raise LdapError, "LDAP: #{@ldap.get_operation_result.message}" unless res
      users
    end

    def retrieve_array_attribute(entry, attribute_name)
      array = entry[attribute_name]
      if array.empty?
        # Possibly an attribute, which must be retrieved in several ranges

        ranged_attr = entry.attribute_names.find { |n| n =~ /\A#{Regexp.escape(attribute_name)};range=/ }
        if ranged_attr
          entry_dn = entry.dn

          loop do
            array += entry[ranged_attr]
            log.debug "retrieved attribute range #{ranged_attr.inspect} of dn #{entry_dn}"

            if ranged_attr =~ /;range=\d+-\*\z/
              break
            end

            attribute_with_range = ranged_attr.to_s.gsub(/;range=.*/, ";range=#{array.size}-*")
            entry = @ldap.search(
              base: entry_dn,
              scope: Net::LDAP::SearchScope_BaseObject,
              attributes: attribute_with_range
            ).first

            ranged_attr = entry.attribute_names.find { |n| n =~ /\A#{Regexp.escape(attribute_name)};range=/ }
          end
        end
      else
        # Values already received -> No ranged attribute
      end
      array
    end

    def search_ldap_groups
      ldap_group_conf = @config[:ldap_groups]
      name_attribute = ldap_group_conf[:name_attribute]
      member_attribute = ldap_group_conf[:member_attribute]

      groups = []
      res = @ldap.search(
        base: ldap_group_conf[:base],
        filter: ldap_group_conf[:filter],
        attributes: [name_attribute, member_attribute, :dn]
      ) do |entry|
        name = entry[name_attribute].first

        unless name
          log.warn "user attribute #{name_attribute.inspect} not defined for #{entry.dn}"
          next
        end

        log.info "found group-dn: #{entry.dn}"

        names = if ldap_group_conf[:bothcase_name]
          [name, name.downcase].uniq
        elsif ldap_group_conf[:lowercase_name]
          [name.downcase]
        else
          [name]
        end

        names.each do |n|
          group_members = retrieve_array_attribute(entry, member_attribute)
          groups << LdapRole.new(n, entry.dn, group_members)
        end
        entry.each do |attribute, values|
          log.debug "   #{attribute}:"
          values.each do |value|
            log.debug "      --->#{value.inspect}"
          end
        end
      end
      raise LdapError, "LDAP: #{@ldap.get_operation_result.message}" unless res
      groups
    end

    PgRole = Struct.new :name, :member_names

    # List of default roles taken from https://www.postgresql.org/docs/current/predefined-roles.html
    PG_BUILTIN_ROLES = %w[pg_read_all_data pg_write_all_data pg_read_all_settings pg_read_all_stats pg_stat_scan_tables pg_monitor pg_database_owner pg_signal_backend pg_read_server_files pg_write_server_files pg_execute_server_program pg_checkpoint pg_create_subscription pg_maintain pg_use_reserved_connections]

    def search_pg_users
      pg_users_conf = @config[:pg_users]

      users = []
      res = pg_exec "SELECT rolname FROM pg_roles WHERE #{pg_users_conf[:filter]}"
      res.each do |tuple|
        user = PgRole.new tuple[0]
        next if PG_BUILTIN_ROLES.include?(user.name)
        log.info { "found pg-user: #{user.name.inspect}" }
        users << user
      end
      users
    end

    def search_pg_groups
      pg_groups_conf = @config[:pg_groups]

      groups = []
      res = pg_exec "SELECT rolname, oid FROM pg_roles WHERE #{pg_groups_conf[:filter]}"
      res.each do |tuple|
        res2 = pg_exec "SELECT pr.rolname FROM pg_auth_members pam JOIN pg_roles pr ON pr.oid=pam.member WHERE pam.roleid=#{@pgconn.escape_string(tuple[1])}"
        member_names = res2.map { |row| row[0] }
        group = PgRole.new tuple[0], member_names
        next if PG_BUILTIN_ROLES.include?(group.name)
        log.info { "found pg-group: #{group.name.inspect} with members: #{member_names.inspect}" }
        groups << group
      end
      groups
    end

    def uniq_names(list)
      names = {}
      list.select do |entry|
        name = entry.name
        if names[name]
          log.warn { "duplicated group/user #{name.inspect} (#{entry.inspect})" }
          next false
        else
          names[name] = true
          next true
        end
      end
    end

    MatchedRole = Struct.new :ldap, :pg, :name, :state, :type

    def match_roles(ldaps, pgs, type)
      ldap_by_name = ldaps.each_with_object({}) { |u, h|
        h[u.name] = u
      }
      pg_by_name = pgs.each_with_object({}) { |u, h|
        h[u.name] = u
      }

      roles = []
      ldaps.each do |ld|
        pg = pg_by_name[ld.name]
        role = MatchedRole.new ld, pg, ld.name
        roles << role
      end
      pgs.each do |pg|
        ld = ldap_by_name[pg.name]
        next if ld
        role = MatchedRole.new ld, pg, pg.name
        roles << role
      end

      roles.each do |r|
        r.state = case
        when r.ldap && !r.pg then :create
        when !r.ldap && r.pg then :drop
        when r.pg && r.ldap then :keep
        else raise "invalid user #{r.inspect}"
        end
        r.type = type
      end

      log.info do
        roles.each do |role|
          log.debug { "#{role.state} #{role.type}: #{role.name}" }
        end
        "#{type} stat: create: #{roles.count { |r| r.state == :create }} drop: #{roles.count { |r| r.state == :drop }} keep: #{roles.count { |r| r.state == :keep }}"
      end
      roles
    end

    def try_sql(text)
      begin
        @pgconn.exec "SAVEPOINT try_sql;"
        @pgconn.exec text
      rescue PG::Error => err
        @pgconn.exec "ROLLBACK TO try_sql;"

        log.error { "#{err} (#{err.class})" }
      end
    end

    def pg_exec_modify(sql)
      log.info { "SQL: #{sql}" }
      unless self.test
        try_sql sql
      end
    end

    def pg_exec(sql)
      res = @pgconn.exec sql
      (0...res.num_tuples).map { |t| (0...res.num_fields).map { |i| res.getvalue(t, i) } }
    end

    def create_pg_role(role)
      pg_conf = @config[(role.type == :user) ? :pg_users : :pg_groups]
      pg_exec_modify "CREATE ROLE \"#{role.name}\" #{pg_conf[:create_options]}"
    end

    def drop_pg_role(role)
      pg_exec_modify "DROP ROLE \"#{role.name}\""
    end

    def sync_roles_to_pg(roles, for_state)
      roles.sort_by(&:name).each do |role|
        create_pg_role(role) if role.state == :create && for_state == :create
        drop_pg_role(role) if role.state == :drop && for_state == :drop
      end
    end

    MatchedMembership = Struct.new :role_name, :has_member, :state

    def match_memberships(ldap_roles, pg_roles)
      hash_of_arrays = Hash.new { |h, k| h[k] = [] }
      ldap_by_dn = ldap_roles.each_with_object(hash_of_arrays) { |r, h|
        h[r.dn] << r
      }
      ldap_by_m2m = ldap_roles.inject([]) do |a, r|
        next a unless r.member_dns
        a + r.member_dns.flat_map do |dn|
          has_members = ldap_by_dn[dn]
          log.warn { "ldap member with dn #{dn} is unknown" } if has_members.empty?
          has_members.map do |has_member|
            [r.name, has_member.name]
          end
        end
      end

      hash_of_arrays = Hash.new { |h, k| h[k] = [] }
      pg_by_name = pg_roles.each_with_object(hash_of_arrays) { |r, h|
        h[r.name] << r
      }
      pg_by_m2m = pg_roles.inject([]) do |a, r|
        next a unless r.member_names
        a + r.member_names.flat_map do |name|
          has_members = pg_by_name[name]
          log.warn { "pg member with name #{name} is unknown" } if has_members.empty?
          has_members.map do |has_member|
            [r.name, has_member.name]
          end
        end
      end

      memberships = (ldap_by_m2m & pg_by_m2m).map { |r, mo| MatchedMembership.new r, mo, :keep }
      memberships += (ldap_by_m2m - pg_by_m2m).map { |r, mo| MatchedMembership.new r, mo, :grant }
      memberships += (pg_by_m2m - ldap_by_m2m).map { |r, mo| MatchedMembership.new r, mo, :revoke }

      log.info do
        memberships.each do |membership|
          log.debug { "#{membership.state} #{membership.role_name} to #{membership.has_member}" }
        end
        "membership stat: grant: #{memberships.count { |u| u.state == :grant }} revoke: #{memberships.count { |u| u.state == :revoke }} keep: #{memberships.count { |u| u.state == :keep }}"
      end
      memberships
    end

    def grant_membership(role_name, add_members)
      pg_conf = @config[:pg_groups]
      add_members_escaped = add_members.map { |m| "\"#{m}\"" }.join(",")
      pg_exec_modify "GRANT \"#{role_name}\" TO #{add_members_escaped} #{pg_conf[:grant_options]}"
    end

    def revoke_membership(role_name, rm_members)
      rm_members_escaped = rm_members.map { |m| "\"#{m}\"" }.join(",")
      pg_exec_modify "REVOKE \"#{role_name}\" FROM #{rm_members_escaped}"
    end

    def sync_membership_to_pg(memberships, for_state)
      grants = {}
      memberships.select { |ms| ms.state == for_state }.each do |ms|
        grants[ms.role_name] ||= []
        grants[ms.role_name] << ms.has_member
      end

      grants.each do |role_name, members|
        grant_membership(role_name, members) if for_state == :grant
        revoke_membership(role_name, members) if for_state == :revoke
      end
    end

    def start!
      read_config_file(@config_fname)

      ldap_conf = @config[:ldap_connection]
      auth_meth = ldap_conf.dig(:auth, :method).to_s
      if auth_meth == "gssapi"
        begin
          require "net/ldap/auth_adapter/gssapi"
        rescue LoadError => err
          raise "#{err}\nTo use GSSAPI authentication please run:\n  gem install net-ldap-auth_adapter-gssapi"
        end
      elsif auth_meth == "gss_spnego"
        begin
          require "net-ldap-gss-spnego"
          # This doesn't work since this file is defined in net-ldap as a placeholder:
          #   require 'net/ldap/auth_adapter/gss_spnego'
        rescue LoadError => err
          raise "#{err}\nTo use GSSAPI authentication please run:\n  gem install net-ldap-gss-spnego"
        end
      end

      # gather LDAP users and groups
      @ldap = Net::LDAP.new ldap_conf
      ldap_users = uniq_names search_ldap_users
      ldap_groups = uniq_names search_ldap_groups

      # gather PGs users and groups
      @pgconn = PG.connect @config[:pg_connection]
      begin
        @pgconn.transaction do
          pg_users = uniq_names search_pg_users
          pg_groups = uniq_names search_pg_groups

          # compare LDAP to PG users and groups
          mroles = match_roles(ldap_users, pg_users, :user)
          mroles += match_roles(ldap_groups, pg_groups, :group)

          # compare LDAP to PG memberships
          mmemberships = match_memberships(ldap_users + ldap_groups, pg_users + pg_groups)

          # drop/revoke roles/memberships first
          sync_membership_to_pg(mmemberships, :revoke)
          sync_roles_to_pg(mroles, :drop)
          # create/grant roles/memberships
          sync_roles_to_pg(mroles, :create)
          sync_membership_to_pg(mmemberships, :grant)
        end
      ensure
        @pgconn.close
      end

      # Determine exitcode
      if log.had_errors?
        raise ErrorExit.new(1, log.first_error)
      end
    end

    def self.run(argv)
      s = new
      s.config_fname = "/etc/pg_ldap_sync.yaml"
      s.log = Logger.new($stdout)
      s.log.level = Logger::ERROR

      OptionParser.new do |opts|
        opts.version = VERSION
        opts.banner = "Usage: #{$0} [options]"
        opts.on("-v", "--[no-]verbose", "Increase verbose level") { |v| s.log.level += v ? -1 : 1 }
        opts.on("-c", "--config FILE", "Config file [#{s.config_fname}]", &s.method(:config_fname=))
        opts.on("-t", "--[no-]test", "Don't do any change in the database", &s.method(:test=))

        opts.parse!(argv)
      end

      s.start!
    end
  end
end
