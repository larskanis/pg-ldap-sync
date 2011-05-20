#!/usr/bin/env ruby

require 'rubygems'
require 'net/ldap'
require 'optparse'
require 'yaml'
require 'logger'
require 'pg'

require 'pg_ldap_sync'

module PgLdapSync
class Application
  attr_accessor :config_fname
  attr_accessor :log
  attr_accessor :test

  def string_to_symbol(hash)
    if hash.kind_of?(Hash)
      return hash.inject({}){|h, v|
        raise "expected String instead of #{h.inspect}" unless v[0].kind_of?(String)
        h[v[0].intern] = string_to_symbol(v[1])
        h
      }
    else
      return hash
    end
  end

  LdapRole = Struct.new :name, :dn, :member_dns

  def search_ldap_users
    ldap_user_conf = @config[:ldap_users]

    users = []
    @ldap.search(:base => ldap_user_conf[:base], :filter => ldap_user_conf[:filter]) do |entry|
      name = entry[ldap_user_conf[:name_attribute]].first

      unless name
        log.warn "user attribute #{ldap_user_conf[:name_attribute].inspect} not found for #{entry.dn}"
        next
      end

      log.info "found user-dn: #{entry.dn}"
      user = LdapRole.new name, entry.dn
      users << user
      entry.each do |attribute, values|
        log.debug "   #{attribute}:"
        values.each do |value|
          log.debug "      --->#{value}"
        end
      end
    end
    return users
  end

  def search_ldap_groups
    ldap_group_conf = @config[:ldap_groups]

    groups = []
    @ldap.search(:base => ldap_group_conf[:base], :filter => ldap_group_conf[:filter]) do |entry|
      name = entry[ldap_group_conf[:name_attribute]].first

      unless name
        log.warn "user attribute #{ldap_group_conf[:name_attribute].inspect} not found for #{entry.dn}"
        next
      end

      log.info "found group-dn: #{entry.dn}"
      group = LdapRole.new name, entry.dn, entry[ldap_group_conf[:member_attribute]]
      groups << group
      entry.each do |attribute, values|
        log.debug "   #{attribute}:"
        values.each do |value|
          log.debug "      --->#{value}"
        end
      end
    end
    return groups
  end

  PgRole = Struct.new :name, :member_names

  def search_pg_users
    pg_users_conf = @config[:pg_users]

    users = []
    res = @pgconn.exec "SELECT * FROM pg_roles WHERE #{pg_users_conf[:filter]}"
    res.each do |tuple|
      user = PgRole.new tuple['rolname']
      log.info{ "found pg-user: #{user.name}"}
      users << user
    end
    return users
  end

  def search_pg_groups
    pg_groups_conf = @config[:pg_groups]

    groups = []
    res = @pgconn.exec "SELECT rolname, oid FROM pg_roles WHERE #{pg_groups_conf[:filter]}"
    res.each do |tuple|
      res2 = @pgconn.exec "SELECT pr.rolname FROM pg_auth_members pam JOIN pg_roles pr ON pr.oid=pam.member WHERE pam.roleid=$1", [{:value=>tuple['oid']}]
      member_names = res2.field_values 'rolname'
      group = PgRole.new tuple['rolname'], member_names
      log.info{ "found pg-group: #{group.name}"}
      groups << group
    end
    return groups
  end

  def uniq_names(list)
    names = {}
    new_list = list.select do |entry|
      name = entry.name
      if names[name]
        log.warn{ "duplicated group/user #{name.inspect} (#{entry.inspect})" }
        next false
      else
        names[name] = true
        next true
      end
    end
    return new_list
  end

  MatchedRole = Struct.new :ldap, :pg, :name, :state, :type

  def match_roles(ldaps, pgs, type)
    ldap_by_name = ldaps.inject({}){|h,u| h[u.name] = u; h }
    pg_by_name = pgs.inject({}){|h,u| h[u.name] = u; h }

    users = []
    ldaps.each do |ld|
      pg = pg_by_name[ld.name]
      user = MatchedRole.new ld, pg, ld.name
      users << user
    end
    pgs.each do |pg|
      ld = ldap_by_name[pg.name]
      next if ld
      user = MatchedRole.new ld, pg, pg.name
      users << user
    end

    users.each do |u|
      u.state = case
        when u.ldap && !u.pg then :create
        when !u.ldap && u.pg then :drop
        when u.pg && u.ldap then :keep
        else raise "invalid user #{u.inspect}"
      end
      u.type = type
    end

    return users
  end

  def pg_exec(sql, params=nil)
    log.info{ "SQL: #{sql}" + (params ? " params: #{params}" : '') }
    unless self.test
      @pgconn.exec sql, params
    end
  end

  def create_pg_role(role)
    pg_conf = @config[role.type==:user ? :pg_users : :pg_groups]
    pg_exec "CREATE ROLE \"#{role.name}\" #{pg_conf[:create_options]}"
  end

  def drop_pg_role(role)
    pg_exec "DROP ROLE \"#{role.name}\""
  end

  def sync_roles_to_pg(roles)
    roles.sort{|a,b|
      t = b.state.to_s<=>a.state.to_s
      t = a.name<=>b.name if t==0
      t
    }.each do |role|
      case role.state
      when :create
        create_pg_role(role)
      when :drop
        drop_pg_role(role)
      end
    end
  end

  MatchedMembership = Struct.new :role_name, :member_of, :state

  def match_memberships(ldap_roles, pg_roles)
    ldap_by_dn = ldap_roles.inject({}){|h,r| h[r.dn] = r; h }
    ldap_by_m2m = ldap_roles.inject([]){|a,r|
      next a unless r.member_dns
      a + r.member_dns.map{|dn|
        if member_of=ldap_by_dn[dn]
          [r.name, member_of.name]
        else
          log.warn{"ldap member with dn #{dn} is unknown"}
          nil
        end
      }.compact
    }

    pg_by_name = pg_roles.inject({}){|h,r| h[r.name] = r; h }
    pg_by_m2m = pg_roles.inject([]){|a,r|
      next a unless r.member_names
      a + r.member_names.map{|name|
        member_of = pg_by_name[name]
        unless member_of
          log.warn{"pg member with name #{name} is unknown"}
        end
        [r.name, member_of.name]
      }.compact
    }

    memberships  = (ldap_by_m2m & pg_by_m2m).map{|r,mo| MatchedMembership.new r, mo, :keep }
    memberships += (ldap_by_m2m - pg_by_m2m).map{|r,mo| MatchedMembership.new r, mo, :grant }
    memberships += (pg_by_m2m - ldap_by_m2m).map{|r,mo| MatchedMembership.new r, mo, :revoke }
    return memberships
  end

  def grant_membership(role_name, add_members)
    pg_conf = @config[:pg_groups]
    add_members_escaped = add_members.map{|m| "\"#{m}\"" }.join(",")
    pg_exec "GRANT \"#{role_name}\" TO #{add_members_escaped} #{pg_conf[:grant_options]}"
  end

  def revoke_membership(role_name, rm_members)
    rm_members_escaped = rm_members.map{|m| "\"#{m}\"" }.join(",")
    pg_exec "REVOKE \"#{role_name}\" FROM #{rm_members_escaped}"
  end

  def sync_membership_to_pg(memberships)
    grants = {}
    memberships.select{|ms| ms.state==:grant }.each do |ms|
      grants[ms.role_name] ||= []
      grants[ms.role_name] << ms.member_of
    end
    revokes = {}
    memberships.select{|ms| ms.state==:revoke }.each do |ms|
      revokes[ms.role_name] ||= []
      revokes[ms.role_name] << ms.member_of
    end

    grants.each{|role_name, members| grant_membership(role_name, members) }
    revokes.each{|role_name, members| revoke_membership(role_name, members) }
  end

  def start!
    raise "Config file #{@config_fname.inspect} does not exist" unless File.exist?(@config_fname)
    @config = string_to_symbol(YAML.load(File.read(@config_fname)))

    @ldap = Net::LDAP.new @config[:ldap_connection]
    ldap_users = uniq_names search_ldap_users
    ldap_groups = uniq_names search_ldap_groups

    @pgconn = PGconn.connect @config[:pg_connection]
    pg_users = uniq_names search_pg_users
    pg_groups = uniq_names search_pg_groups

    mroles = match_roles(ldap_users, pg_users, :user)
    mroles += match_roles(ldap_groups, pg_groups, :group)
    log.info{
      mroles.each do |mrole|
        log.debug{ "#{mrole.state} #{mrole.type}: #{mrole.name}" }
      end
      "user/group stat: create: #{mroles.count{|u| u.state==:create }} drop: #{mroles.count{|u| u.state==:drop }} keep: #{mroles.count{|u| u.state==:keep }}"
    }

    mmemberships = match_memberships(ldap_users+ldap_groups, pg_users+pg_groups)
    log.info{
      mmemberships.each do |mmembership|
        log.debug{ "#{mmembership.state} #{mmembership.role_name} to #{mmembership.member_of}" }
      end
      "membership stat: grant: #{mmemberships.count{|u| u.state==:grant }} revoke: #{mmemberships.count{|u| u.state==:revoke }} keep: #{mmemberships.count{|u| u.state==:keep }}"
    }

    sync_roles_to_pg(mroles)
    sync_membership_to_pg(mmemberships)
  end

  def self.run(argv)
    s = self.new
    s.config_fname = '/etc/pg_ldap_sync.yaml'
    s.log = Logger.new(STDOUT)
    s.log.level = Logger::ERROR

    OptionParser.new(argv) do |opts|
      opts.banner = "Usage: #{$0} [options]"
      opts.on("-v", "--[no-]verbose", "Be more verbose"){ s.log.level-=1 }
      opts.on("-c", "--config FILE", "Config file [#{s.config_fname}]", &s.method(:config_fname=))
      opts.on("-t", "--[no-]test", "Don't do any change in the database", &s.method(:test=))

      opts.parse!
    end

    s.start!
  end
end
end
