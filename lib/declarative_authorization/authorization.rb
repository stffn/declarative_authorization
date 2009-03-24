# Authorization
require File.dirname(__FILE__) + '/reader.rb'
require "set"


module Authorization
  # An exception raised if anything goes wrong in the Authorization realm
  class AuthorizationError < StandardError ; end
  # NotAuthorized is raised if the current user is not allowed to perform
  # the given operation possibly on a specific object.
  class NotAuthorized < AuthorizationError ; end
  # AttributeAuthorizationError is more specific than NotAuthorized, signalling
  # that the access was denied on the grounds of attribute conditions.
  class AttributeAuthorizationError < NotAuthorized ; end
  # AuthorizationUsageError is used whenever a situation is encountered
  # in which the application misused the plugin.  That is, if, e.g.,
  # authorization rules may not be evaluated.
  class AuthorizationUsageError < AuthorizationError ; end
  # NilAttributeValueError is raised by Attribute#validate? when it hits a nil attribute value.
  # The exception is raised to ensure that the entire rule is invalidated.
  class NilAttributeValueError < AuthorizationError; end
  
  AUTH_DSL_FILE = "#{RAILS_ROOT}/config/authorization_rules.rb"
  
  # Controller-independent method for retrieving the current user.
  # Needed for model security where the current controller is not available.
  def self.current_user
    Thread.current["current_user"] || GuestUser.new
  end
  
  # Controller-independent method for setting the current user.
  def self.current_user=(user)
    Thread.current["current_user"] = user
  end
  
  @@ignore_access_control = false
  # For use in test cases only
  def self.ignore_access_control (state = nil) # :nodoc:
    false
  end

  def self.activate_authorization_rules_browser? # :nodoc:
    ::RAILS_ENV == 'development'
  end

  @@dot_path = "dot"
  def self.dot_path
    @@dot_path
  end

  def self.dot_path= (path)
    @@dot_path = path
  end
  
  # Authorization::Engine implements the reference monitor.  It may be used
  # for querying the permission and retrieving obligations under which
  # a certain privilege is granted for the current user.
  #
  class Engine
    attr_reader :roles, :role_titles, :role_descriptions, :privileges,
      :privilege_hierarchy, :auth_rules, :role_hierarchy, :rev_priv_hierarchy
    
    # If +reader+ is not given, a new one is created with the default
    # authorization configuration of +AUTH_DSL_FILE+.  If given, may be either
    # a Reader object or a path to a configuration file.
    def initialize (reader = nil)
      if reader.nil?
        begin
          reader = Reader::DSLReader.load(AUTH_DSL_FILE)
        rescue SystemCallError
          reader = Reader::DSLReader.new
        end
      elsif reader.is_a?(String)
        reader = Reader::DSLReader.load(reader)
      end
      @privileges = reader.privileges_reader.privileges
      # {priv => [[priv, ctx],...]}
      @privilege_hierarchy = reader.privileges_reader.privilege_hierarchy
      @auth_rules = reader.auth_rules_reader.auth_rules
      @roles = reader.auth_rules_reader.roles
      @role_hierarchy = reader.auth_rules_reader.role_hierarchy

      @role_titles = reader.auth_rules_reader.role_titles
      @role_descriptions = reader.auth_rules_reader.role_descriptions
      
      # {[priv, ctx] => [priv, ...]}
      @rev_priv_hierarchy = {}
      @privilege_hierarchy.each do |key, value|
        value.each do |val| 
          @rev_priv_hierarchy[val] ||= []
          @rev_priv_hierarchy[val] << key
        end
      end
    end
    
    # Returns true if privilege is met by the current user.  Raises
    # AuthorizationError otherwise.  +privilege+ may be given with or
    # without context.  In the latter case, the :+context+ option is
    # required.
    #  
    # Options:
    # [:+context+]
    #   The context part of the privilege.
    #   Defaults either to the +table_name+ of the given :+object+, if given.
    #   That is, either :+users+ for :+object+ of type User.  
    #   Raises AuthorizationUsageError if
    #   context is missing and not to be infered.
    # [:+object+] An context object to test attribute checks against.
    # [:+skip_attribute_test+]
    #   Skips those attribute checks in the 
    #   authorization rules. Defaults to false.
    # [:+user+] 
    #   The user to check the authorization for.
    #   Defaults to Authorization#current_user.
    #
    def permit! (privilege, options = {})
      return true if Authorization.ignore_access_control
      options = {
        :object => nil,
        :skip_attribute_test => false,
        :context => nil
      }.merge(options)
      
      # Make sure we're handling all privileges as symbols.
      privilege = privilege.is_a?( Array ) ?
                  privilege.flatten.collect { |priv| priv.to_sym } :
                  privilege.to_sym
      
      #
      # If the object responds to :proxy_reflection, we're probably working with
      # an association proxy.  Use 'new' to leverage ActiveRecord's builder
      # functionality to obtain an object against which we can check permissions.
      #
      # Example: permit!( :edit, :object => user.posts )
      #
      if options[:object].respond_to?( :proxy_reflection ) && options[:object].respond_to?( :new )
        options[:object] = options[:object].new
      end
      
      options[:context] ||= options[:object] && options[:object].class.table_name.to_sym rescue NoMethodError
      
      user, roles, privileges = user_roles_privleges_from_options(privilege, options)

      # find a authorization rule that matches for at least one of the roles and 
      # at least one of the given privileges
      attr_validator = AttributeValidator.new(self, user, options[:object])
      rules = matching_auth_rules(roles, privileges, options[:context])
      if rules.empty?
        raise NotAuthorized, "No matching rules found for #{privilege} for #{user.inspect} " +
          "(roles #{roles.inspect}, privileges #{privileges.inspect}, " +
          "context #{options[:context].inspect})."
      end
      
      # Test each rule in turn to see whether any one of them is satisfied.
      grant_permission = rules.any? do |rule|
        begin
          options[:skip_attribute_test] or
            rule.attributes.empty? or
            rule.attributes.any? do |attr|
              begin
                attr.validate?( attr_validator )
              rescue NilAttributeValueError => e
                nil # Bumping up against a nil attribute value flunks the rule.
              end
            end
        end
      end
      unless grant_permission
        raise AttributeAuthorizationError, "#{privilege} not allowed for #{user.inspect} on #{options[:object].inspect}."
      end
      true
    end
    
    # Calls permit! but rescues the AuthorizationException and returns false
    # instead.  If no exception is raised, permit? returns true and yields
    # to the optional block.
    def permit? (privilege, options = {}, &block) # :yields:
      permit!(privilege, options)
      yield if block_given?
      true
    rescue NotAuthorized
      false
    end
    
    # Returns the obligations to be met by the current user for the given 
    # privilege as an array of obligation hashes in form of 
    #   [{:object_attribute => obligation_value, ...}, ...]
    # where +obligation_value+ is either (recursively) another obligation hash
    # or a value spec, such as
    #   [operator, literal_value]
    # The obligation hashes in the array should be OR'ed, conditions inside
    # the hashes AND'ed.
    # 
    # Example
    #   {:branch => {:company => [:is, 24]}, :active => [:is, true]}
    # 
    # Options
    # [:+context+]  See permit!
    # [:+user+]  See permit!
    # 
    def obligations (privilege, options = {})
      options = {:context => nil}.merge(options)
      user, roles, privileges = user_roles_privleges_from_options(privilege, options)
      attr_validator = AttributeValidator.new(self, user, nil, options[:context])
      matching_auth_rules(roles, privileges, options[:context]).collect do |rule|
        obligation = rule.attributes.collect {|attr| attr.obligation(attr_validator) }
        obligation.empty? ? [{}] : obligation
      end.flatten
    end
    
    # Returns the description for the given role.  The description may be
    # specified with the authorization rules.  Returns +nil+ if none was
    # given.
    def description_for (role)
      role_descriptions[role]
    end
    
    # Returns the title for the given role.  The title may be
    # specified with the authorization rules.  Returns +nil+ if none was
    # given.
    def title_for (role)
      role_titles[role]
    end

    # Returns the role symbols of the given user.
    def roles_for (user)
      raise AuthorizationUsageError, "User object doesn't respond to roles" \
        if !user.respond_to?(:role_symbols) and !user.respond_to?(:roles)

      RAILS_DEFAULT_LOGGER.info("The use of user.roles is deprecated.  Please add a method " +
          "role_symbols to your User model.") if defined?(RAILS_DEFAULT_LOGGER) and !user.respond_to?(:role_symbols)

      roles = user.respond_to?(:role_symbols) ? user.role_symbols : user.roles

      raise AuthorizationUsageError, "User.#{user.respond_to?(:role_symbols) ? 'role_symbols' : 'roles'} " +
        "doesn't return an Array of Symbols (#{roles.inspect})" \
            if !roles.is_a?(Array) or (!roles.empty? and !roles[0].is_a?(Symbol))

      (roles.empty? ? [:guest] : roles)
    end
    
    # Returns the role symbols and inherritted role symbols for the given user
    def roles_with_hierarchy_for(user)
      flatten_roles(roles_for(user))
    end
    
    # Returns an instance of Engine, which is created if there isn't one
    # yet.  If +dsl_file+ is given, it is passed on to Engine.new and 
    # a new instance is always created.
    def self.instance (dsl_file = nil)
      if dsl_file or ENV['RAILS_ENV'] == 'development'
        @@instance = new(dsl_file)
      else
        @@instance ||= new
      end
    end
    
    class AttributeValidator # :nodoc:
      attr_reader :user, :object, :engine, :context
      def initialize (engine, user, object = nil, context = nil)
        @engine = engine
        @user = user
        @object = object
        @context = context
      end
      
      def evaluate (value_block)
        # TODO cache?
        instance_eval(&value_block)
      end
    end
    
    private
    def user_roles_privleges_from_options(privilege, options)
      options = {
        :user => nil,
        :context => nil
      }.merge(options)
      user = options[:user] || Authorization.current_user
      privileges = privilege.is_a?(Array) ? privilege : [privilege]
      
      raise AuthorizationUsageError, "No user object given (#{user.inspect})" \
        unless user

      roles = flatten_roles(roles_for(user))
      privileges = flatten_privileges privileges, options[:context]
      [user, roles, privileges]
    end
    
    def flatten_roles (roles)
      # TODO caching?
      flattened_roles = roles.clone.to_a
      flattened_roles.each do |role|
        flattened_roles.concat(@role_hierarchy[role]).uniq! if @role_hierarchy[role]
      end
    end
    
    # Returns the privilege hierarchy flattened for given privileges in context.
    def flatten_privileges (privileges, context = nil)
      # TODO caching?
      #if context.nil?
      #  context = privileges.collect { |p| p.to_s.split('_') }.
      #                       reject { |p_p| p_p.length < 2 }.
      #                       collect { |p_p| (p_p[1..-1] * '_').to_sym }.first
      #  raise AuthorizationUsageError, "No context given or inferable from privileges #{privileges.inspect}" unless context
      #end
      raise AuthorizationUsageError, "No context given or inferable from object" unless context
      #context_regex = Regexp.new "_#{context}$"
      # TODO work with contextless privileges
      #flattened_privileges = privileges.collect {|p| p.to_s.sub(context_regex, '')}
      flattened_privileges = privileges.clone #collect {|p| p.to_s.end_with?(context.to_s) ?
                                              #       p : [p, "#{p}_#{context}".to_sym] }.flatten
      flattened_privileges.each do |priv|
        flattened_privileges.concat(@rev_priv_hierarchy[[priv, nil]]).uniq! if @rev_priv_hierarchy[[priv, nil]]
        flattened_privileges.concat(@rev_priv_hierarchy[[priv, context]]).uniq! if @rev_priv_hierarchy[[priv, context]]
      end
    end
    
    def matching_auth_rules (roles, privileges, context)
      @auth_rules.select {|rule| rule.matches? roles, privileges, context}
    end
  end
  
  class AuthorizationRule
    attr_reader :attributes, :contexts, :role, :privileges
    
    def initialize (role, privileges = [], contexts = nil)
      @role = role
      @privileges = Set.new(privileges)
      @contexts = Set.new((contexts && !contexts.is_a?(Array) ? [contexts] : contexts))
      @attributes = []
    end
    
    def append_privileges (privs)
      @privileges.merge(privs)
    end
    
    def append_attribute (attribute)
      @attributes << attribute
    end
    
    def matches? (roles, privs, context = nil)
      roles = [roles] unless roles.is_a?(Array)
      @contexts.include?(context) and roles.include?(@role) and 
        not (@privileges & privs).empty?
    end

    def to_long_s
      attributes.collect {|attr| attr.to_long_s } * "; "
    end
  end
  
  class Attribute
    # attr_conditions_hash of form
    # { :object_attribute => [operator, value_block], ... }
    # { :object_attribute => { :attr => ... } }
    def initialize (conditions_hash)
      @conditions_hash = conditions_hash
    end
    
    def validate? (attr_validator, object = nil, hash = nil)
      object ||= attr_validator.object
      return false unless object
      
      (hash || @conditions_hash).all? do |attr, value|
        attr_value = object_attribute_value(object, attr)
        if value.is_a?(Hash)
          if attr_value.is_a?(Array)
            raise AuthorizationUsageError, "Unable evaluate multiple attributes " +
              "on a collection.  Cannot use '=>' operator on #{attr.inspect} " +
              "(#{attr_value.inspect}) for attributes #{value.inspect}."
          elsif attr_value.nil?
            raise NilAttributeValueError, "Attribute #{attr.inspect} is nil in #{object.inspect}."
          end
          validate?(attr_validator, attr_value, value)
        elsif value.is_a?(Array) and value.length == 2
          evaluated = if value[1].is_a?(Proc)
                        attr_validator.evaluate(value[1])
                      else
                        value[1]
                      end
          case value[0]
          when :is
            attr_value == evaluated
          when :is_not
            attr_value != evaluated
          when :contains
            attr_value.include?(evaluated)
          when :does_not_contain
            !attr_value.include?(evaluated)
          when :is_in
            evaluated.include?(attr_value)
          when :is_not_in
            !evaluated.include?(attr_value)
          else
            raise AuthorizationError, "Unknown operator #{value[0]}"
          end
        else
          raise AuthorizationError, "Wrong conditions hash format"
        end
      end
    end
    
    # resolves all the values in condition_hash
    def obligation (attr_validator, hash = nil)
      hash = (hash || @conditions_hash).clone
      hash.each do |attr, value|
        if value.is_a?(Hash)
          hash[attr] = obligation(attr_validator, value)
        elsif value.is_a?(Array) and value.length == 2
          hash[attr] = [value[0], attr_validator.evaluate(value[1])]
        else
          raise AuthorizationError, "Wrong conditions hash format"
        end
      end
      hash
    end

    def to_long_s (hash = nil)
      if hash
        hash.inject({}) do |memo, key_val|
          key, val = key_val
          memo[key] = case val
                      when Array then "#{val[0]} { #{val[1].respond_to?(:to_ruby) ? val[1].to_ruby.gsub(/^proc \{\n?(.*)\n?\}$/m, '\1') : "..."} }"
                      when Hash then to_long_s(val)
                      end
          memo
        end
      else
        "if_attribute #{to_long_s(@conditions_hash).inspect}"
      end
    end

    protected
    def object_attribute_value (object, attr)
      begin
        object.send(attr)
      rescue ArgumentError, NoMethodError => e
        raise AuthorizationUsageError, "Error when calling #{attr} on " +
         "#{object.inspect} for validating attribute: #{e}"
      end
    end
  end

  # An attribute condition that uses existing rules to decide validation
  # and create obligations.
  class AttributeWithPermission < Attribute
    # E.g. privilege :read, attr_or_hash either :attribute or
    # { :attribute => :deeper_attribute }
    def initialize (privilege, attr_or_hash, context = nil)
      @privilege = privilege
      @context = context
      @attr_hash = attr_or_hash
    end

    def validate? (attr_validator, object = nil, hash_or_attr = nil)
      object ||= attr_validator.object
      hash_or_attr ||= @attr_hash
      return false unless object

      case hash_or_attr
      when Symbol
        attr_value = object_attribute_value(object, hash_or_attr)
        if attr_value.nil?
          raise NilAttributeValueError, "Attribute #{hash_or_attr.inspect} is nil in #{object.inspect}."
        end
        attr_validator.engine.permit? @privilege, :object => attr_value, :user => attr_validator.user
      when Hash
        hash_or_attr.all? do |attr, sub_hash|
          attr_value = object_attribute_value(object, attr)
          if attr_value.nil?
            raise NilAttributeValueError, "Attribute #{attr.inspect} is nil in #{object.inspect}."
          end
          validate?(attr_validator, attr_value, sub_hash)
        end
      when NilClass
        attr_validator.engine.permit? @privilege, :object => object, :user => attr_validator.user
      else
        raise AuthorizationError, "Wrong conditions hash format: #{hash_or_attr.inspect}"
      end
    end

    # may return an array of obligations to be OR'ed
    def obligation (attr_validator, hash_or_attr = nil)
      hash_or_attr ||= @attr_hash
      case hash_or_attr
      when Symbol
        obligations = attr_validator.engine.obligations(@privilege,
                          :context => @context || hash_or_attr.to_s.pluralize.to_sym,
                          :user    => attr_validator.user)
        obligations.collect {|obl| {hash_or_attr => obl} }
      when Hash
        obligations_array_attrs = []
        obligations =
            hash_or_attr.inject({}) do |all, pair|
              attr, sub_hash = pair
              all[attr] = obligation(attr_validator, sub_hash)
              if all[attr].length > 1
                obligations_array_attrs << attr
              else
                all[attr] = all[attr].first
              end
              all
            end
        obligations = [obligations]
        obligations_array_attrs.each do |attr|
          next_array_size = obligations.first[attr].length
          obligations = obligations.collect do |obls|
            (0...next_array_size).collect do |idx|
              obls_wo_array = obls.clone
              obls_wo_array[attr] = obls_wo_array[attr][idx]
              obls_wo_array
            end
          end.flatten
        end
        obligations
      when NilClass
        attr_validator.engine.obligations(@privilege,
            :context => attr_validator.context,
            :user    => attr_validator.user)
      else
        raise AuthorizationError, "Wrong conditions hash format: #{hash_or_attr.inspect}"
      end
    end

    def to_long_s
      "if_permitted_to #{@privilege.inspect}, #{@attr_hash.inspect}"
    end
  end
  
  # Represents a pseudo-user to facilitate guest users in applications
  class GuestUser
    attr_reader :role_symbols
    def initialize (roles = [:guest])
      @role_symbols = roles
    end
  end
end
