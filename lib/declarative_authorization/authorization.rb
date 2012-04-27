# Authorization
require File.dirname(__FILE__) + '/reader.rb'
require "set"
require "forwardable"

module Authorization
  # An exception raised if anything goes wrong in the Authorization realm
  class AuthorizationError < StandardError ; end
  # NotAuthorized is raised if the current user is not allowed to perform
  # the given operation possibly on a specific object.
  class NotAuthorized < AuthorizationError ; end
  # AttributeAuthorizationError is more specific than NotAuthorized, signaling
  # that the access was denied on the grounds of attribute conditions.
  class AttributeAuthorizationError < NotAuthorized ; end
  # AuthorizationUsageError is used whenever a situation is encountered
  # in which the application misused the plugin.  That is, if, e.g.,
  # authorization rules may not be evaluated.
  class AuthorizationUsageError < AuthorizationError ; end
  # NilAttributeValueError is raised by Attribute#validate? when it hits a nil attribute value.
  # The exception is raised to ensure that the entire rule is invalidated.
  class NilAttributeValueError < AuthorizationError; end
  
  AUTH_DSL_FILES = [Pathname.new(Rails.root || '').join("config", "authorization_rules.rb").to_s] unless defined? AUTH_DSL_FILES
  
  # Controller-independent method for retrieving the current user.
  # Needed for model security where the current controller is not available.
  def self.current_user
    Thread.current["current_user"] || AnonymousUser.new
  end
  
  # Controller-independent method for setting the current user.
  def self.current_user=(user)
    Thread.current["current_user"] = user
  end
  
  # For use in test cases only
  def self.ignore_access_control (state = nil) # :nodoc:
    Thread.current["ignore_access_control"] = state unless state.nil?
    Thread.current["ignore_access_control"] || false
  end

  def self.activate_authorization_rules_browser? # :nodoc:
    ::Rails.env.development?
  end

  @@dot_path = "dot"
  def self.dot_path
    @@dot_path
  end

  def self.dot_path= (path)
    @@dot_path = path
  end
  
  @@default_role = :guest
  def self.default_role
    @@default_role
  end

  def self.default_role= (role)
    @@default_role = role.to_sym
  end

  def self.is_a_association_proxy? (object)
    if Rails.version < "3.2"
      object.respond_to?(:proxy_reflection)
    else
      object.respond_to?(:proxy_association)
    end
  end
  
  # Authorization::Engine implements the reference monitor.  It may be used
  # for querying the permission and retrieving obligations under which
  # a certain privilege is granted for the current user.
  #
  class Engine
    extend Forwardable
    attr_reader :reader

    def_delegators :@reader, :auth_rules_reader, :privileges_reader, :load, :load!
    def_delegators :auth_rules_reader, :auth_rules, :roles, :omnipotent_roles, :role_hierarchy, :role_titles, :role_descriptions
    def_delegators :privileges_reader, :privileges, :privilege_hierarchy
    
    # If +reader+ is not given, a new one is created with the default
    # authorization configuration of +AUTH_DSL_FILES+.  If given, may be either
    # a Reader object or a path to a configuration file.
    def initialize (reader = nil)
      #@auth_rules = AuthorizationRuleSet.new reader.auth_rules_reader.auth_rules
      @reader = Reader::DSLReader.factory(reader || AUTH_DSL_FILES)
    end

    def initialize_copy (from) # :nodoc:
      @reader = from.reader.clone
    end

    # {[priv, ctx] => [priv, ...]}
    def rev_priv_hierarchy
      if @rev_priv_hierarchy.nil?
        @rev_priv_hierarchy = {}
        privilege_hierarchy.each do |key, value|
          value.each do |val| 
            @rev_priv_hierarchy[val] ||= []
            @rev_priv_hierarchy[val] << key
          end
        end
      end
      @rev_priv_hierarchy
    end
   
    # {[priv, ctx] => [priv, ...]}
    def rev_role_hierarchy  
      if @rev_role_hierarchy.nil?
        @rev_role_hierarchy = {}
        role_hierarchy.each do |higher_role, lower_roles|
          lower_roles.each do |role|
            (@rev_role_hierarchy[role] ||= []) << higher_role
          end
        end
      end
      @rev_role_hierarchy
    end
    
    # Returns true if privilege is met by the current user.  Raises
    # AuthorizationError otherwise.  +privilege+ may be given with or
    # without context.  In the latter case, the :+context+ option is
    # required.
    #  
    # Options:
    # [:+context+]
    #   The context part of the privilege.
    #   Defaults either to the tableized +class_name+ of the given :+object+, if given.
    #   That is, :+users+ for :+object+ of type User.  
    #   Raises AuthorizationUsageError if context is missing and not to be inferred.
    # [:+object+] An context object to test attribute checks against.
    # [:+skip_attribute_test+]
    #   Skips those attribute checks in the 
    #   authorization rules. Defaults to false.
    # [:+user+] 
    #   The user to check the authorization for.
    #   Defaults to Authorization#current_user.
    # [:+bang+]
    #   Should NotAuthorized exceptions be raised
    #   Defaults to true.
    #
    def permit! (privilege, options = {})
      return true if Authorization.ignore_access_control
      options = {
        :object => nil,
        :skip_attribute_test => false,
        :context => nil,
        :bang => true
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
      if Authorization.is_a_association_proxy?(options[:object]) && options[:object].respond_to?(:new)
        options[:object] = options[:object].new
      end
      
      options[:context] ||= options[:object] && (
        options[:object].class.respond_to?(:decl_auth_context) ?
            options[:object].class.decl_auth_context :
            options[:object].class.name.tableize.to_sym
      ) rescue NoMethodError
      
      user, roles, privileges = user_roles_privleges_from_options(privilege, options)

      return true if roles.is_a?(Array) and not (roles & omnipotent_roles).empty?

      # find a authorization rule that matches for at least one of the roles and 
      # at least one of the given privileges
      attr_validator = AttributeValidator.new(self, user, options[:object], privilege, options[:context])
      rules = matching_auth_rules(roles, privileges, options[:context])
      
      # Test each rule in turn to see whether any one of them is satisfied.
      rules.each do |rule|
        return true if rule.validate?(attr_validator, options[:skip_attribute_test])
      end

      if options[:bang]
        if rules.empty?
          raise NotAuthorized, "No matching rules found for #{privilege} for #{user.inspect} " +
            "(roles #{roles.inspect}, privileges #{privileges.inspect}, " +
            "context #{options[:context].inspect})."
        else
          raise AttributeAuthorizationError, "#{privilege} not allowed for #{user.inspect} on #{(options[:object] || options[:context]).inspect}."
        end
      else
        false
      end
    end
    
    # Calls permit! but doesn't raise authorization errors. If no exception is
    # raised, permit? returns true and yields  to the optional block.
    def permit? (privilege, options = {}) # :yields:
      if permit!(privilege, options.merge(:bang=> false))
        yield if block_given?
        true
      else
        false
      end
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

      permit!(privilege, :skip_attribute_test => true, :user => user, :context => options[:context])
      
      return [] if roles.is_a?(Array) and not (roles & omnipotent_roles).empty?
      
      attr_validator = AttributeValidator.new(self, user, nil, privilege, options[:context])
      matching_auth_rules(roles, privileges, options[:context]).collect do |rule|
        rule.obligations(attr_validator)
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
      user ||= Authorization.current_user
      raise AuthorizationUsageError, "User object doesn't respond to roles (#{user.inspect})" \
        if !user.respond_to?(:role_symbols) and !user.respond_to?(:roles)

      Rails.logger.info("The use of user.roles is deprecated.  Please add a method " +
          "role_symbols to your User model.") if defined?(Rails) and Rails.respond_to?(:logger) and !user.respond_to?(:role_symbols)

      roles = user.respond_to?(:role_symbols) ? user.role_symbols : user.roles

      raise AuthorizationUsageError, "User.#{user.respond_to?(:role_symbols) ? 'role_symbols' : 'roles'} " +
        "doesn't return an Array of Symbols (#{roles.inspect})" \
            if !roles.is_a?(Array) or (!roles.empty? and !roles[0].is_a?(Symbol))

      (roles.empty? ? [Authorization.default_role] : roles)
    end
    
    # Returns the role symbols and inherritted role symbols for the given user
    def roles_with_hierarchy_for(user)
      flatten_roles(roles_for(user))
    end

    def self.development_reload?
      if Rails.env.development?
        mod_time = AUTH_DSL_FILES.map { |m| File.mtime(m) rescue Time.at(0) }.flatten.max
        @@auth_dsl_last_modified ||= mod_time
        if mod_time > @@auth_dsl_last_modified
          @@auth_dsl_last_modified = mod_time
          return true
        end
      end
    end

    # Returns an instance of Engine, which is created if there isn't one
    # yet.  If +dsl_file+ is given, it is passed on to Engine.new and 
    # a new instance is always created.
    def self.instance (dsl_file = nil)
      if dsl_file or development_reload?
        @@instance = new(dsl_file)
      else
        @@instance ||= new
      end
    end
    
    class AttributeValidator # :nodoc:
      attr_reader :user, :object, :engine, :context, :privilege
      def initialize (engine, user, object = nil, privilege = nil, context = nil)
        @engine = engine
        @user = user
        @object = object
        @privilege = privilege
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
        :context => nil,
        :user_roles => nil
      }.merge(options)
      user = options[:user] || Authorization.current_user
      privileges = privilege.is_a?(Array) ? privilege : [privilege]
      
      raise AuthorizationUsageError, "No user object given (#{user.inspect}) or " +
        "set through Authorization.current_user" unless user

      roles = options[:user_roles] || flatten_roles(roles_for(user))
      privileges = flatten_privileges privileges, options[:context]
      [user, roles, privileges]
    end
    
    def flatten_roles (roles, flattened_roles = Set.new)
      # TODO caching?
      roles.reject {|role| flattened_roles.include?(role)}.each do |role|
        flattened_roles << role
        flatten_roles(role_hierarchy[role], flattened_roles) if role_hierarchy[role]
      end
      flattened_roles.to_a
    end
    
    # Returns the privilege hierarchy flattened for given privileges in context.
    def flatten_privileges (privileges, context = nil, flattened_privileges = Set.new)
      # TODO caching?
      raise AuthorizationUsageError, "No context given or inferable from object" unless context
      privileges.reject {|priv| flattened_privileges.include?(priv)}.each do |priv|
        flattened_privileges << priv
        flatten_privileges(rev_priv_hierarchy[[priv, nil]], context, flattened_privileges) if rev_priv_hierarchy[[priv, nil]]
        flatten_privileges(rev_priv_hierarchy[[priv, context]], context, flattened_privileges) if rev_priv_hierarchy[[priv, context]]
      end
      flattened_privileges.to_a
    end
    
    def matching_auth_rules (roles, privileges, context)
      auth_rules.matching(roles, privileges, context)
    end
  end
  

  class AuthorizationRuleSet
    include Enumerable
    extend Forwardable
    def_delegators :@rules, :each, :length, :[]

    def initialize (rules = [])
      @rules = rules.clone
      reset!
    end

    def initialize_copy (source)
      @rules = @rules.collect {|rule| rule.clone}
      reset!
    end

    def matching(roles, privileges, context)
      roles = [roles] unless roles.is_a?(Array)
      rules = cached_auth_rules[context] || []
      rules.select do |rule|
        rule.matches? roles, privileges, context
      end
    end
    def delete rule
      @rules.delete rule
      reset!
    end
    def << rule
      @rules << rule
      reset!
    end
    def each &block
      @rules.each &block
    end

    private
    def reset!
      @cached_auth_rules =nil
    end
    def cached_auth_rules
      return @cached_auth_rules if @cached_auth_rules
      @cached_auth_rules = {}
      @rules.each do |rule|
        rule.contexts.each do |context|
          @cached_auth_rules[context] ||= []
          @cached_auth_rules[context] << rule
        end
      end
      @cached_auth_rules
    end
  end
  class AuthorizationRule
    attr_reader :attributes, :contexts, :role, :privileges, :join_operator,
        :source_file, :source_line
    
    def initialize (role, privileges = [], contexts = nil, join_operator = :or,
          options = {})
      @role = role
      @privileges = Set.new(privileges)
      @contexts = Set.new((contexts && !contexts.is_a?(Array) ? [contexts] : contexts))
      @join_operator = join_operator
      @attributes = []
      @source_file = options[:source_file]
      @source_line = options[:source_line]
    end

    def initialize_copy (from)
      @privileges = @privileges.clone
      @contexts = @contexts.clone
      @attributes = @attributes.collect {|attribute| attribute.clone }
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

    def validate? (attr_validator, skip_attribute = false)
      skip_attribute or @attributes.empty? or
        @attributes.send(@join_operator == :and ? :all? : :any?) do |attr|
          begin
            attr.validate?(attr_validator)
          rescue NilAttributeValueError => e
            nil # Bumping up against a nil attribute value flunks the rule.
          end
        end
    end

    def obligations (attr_validator)
      exceptions = []
      obligations = @attributes.collect do |attr|
        begin
          attr.obligation(attr_validator)
        rescue NotAuthorized => e
          exceptions << e
          nil
        end
      end

      if exceptions.length > 0 and (@join_operator == :and or exceptions.length == @attributes.length)
        raise NotAuthorized, "Missing authorization in collecting obligations: #{exceptions.map(&:to_s) * ", "}"
      end

      if @join_operator == :and and !obligations.empty?
        # cross product of OR'ed obligations in arrays
        arrayed_obligations = obligations.map {|obligation| obligation.is_a?(Hash) ? [obligation] : obligation}
        merged_obligations = arrayed_obligations.first
        arrayed_obligations[1..-1].each do |inner_obligations|
          previous_merged_obligations = merged_obligations
          merged_obligations = inner_obligations.collect do |inner_obligation|
            previous_merged_obligations.collect do |merged_obligation|
              merged_obligation.deep_merge(inner_obligation)
            end
          end.flatten
        end
        obligations = merged_obligations
      else
        obligations = obligations.flatten.compact
      end
      obligations.empty? ? [{}] : obligations
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

    def initialize_copy (from)
      @conditions_hash = deep_hash_clone(@conditions_hash)
    end
    
    def validate? (attr_validator, object = nil, hash = nil)
      object ||= attr_validator.object
      return false unless object
      
      (hash || @conditions_hash).all? do |attr, value|
        attr_value = object_attribute_value(object, attr)
        if value.is_a?(Hash)
          if attr_value.is_a?(Enumerable)
            attr_value.any? do |inner_value|
              validate?(attr_validator, inner_value, value)
            end
          elsif attr_value == nil
            raise NilAttributeValueError, "Attribute #{attr.inspect} is nil in #{object.inspect}."
          else
            validate?(attr_validator, attr_value, value)
          end
        elsif value.is_a?(Array) and value.length == 2 and value.first.is_a?(Symbol)
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
            begin
              attr_value.include?(evaluated)
            rescue NoMethodError => e
              raise AuthorizationUsageError, "Operator contains requires a " +
                  "subclass of Enumerable as attribute value, got: #{attr_value.inspect} " +
                  "contains #{evaluated.inspect}: #{e}"
            end
          when :does_not_contain
            begin
              !attr_value.include?(evaluated)
            rescue NoMethodError => e
              raise AuthorizationUsageError, "Operator does_not_contain requires a " +
                  "subclass of Enumerable as attribute value, got: #{attr_value.inspect} " +
                  "does_not_contain #{evaluated.inspect}: #{e}"
            end
          when :intersects_with
            begin
              !(evaluated.to_set & attr_value.to_set).empty?
            rescue NoMethodError => e
              raise AuthorizationUsageError, "Operator intersects_with requires " +
                  "subclasses of Enumerable, got: #{attr_value.inspect} " +
                  "intersects_with #{evaluated.inspect}: #{e}"
            end
          when :is_in
            begin
              evaluated.include?(attr_value)
            rescue NoMethodError => e
              raise AuthorizationUsageError, "Operator is_in requires a " +
                  "subclass of Enumerable as value, got: #{attr_value.inspect} " +
                  "is_in #{evaluated.inspect}: #{e}"
            end
          when :is_not_in
            begin
              !evaluated.include?(attr_value)
            rescue NoMethodError => e
              raise AuthorizationUsageError, "Operator is_not_in requires a " +
                  "subclass of Enumerable as value, got: #{attr_value.inspect} " +
                  "is_not_in #{evaluated.inspect}: #{e}"
            end
          when :lt
            attr_value && attr_value < evaluated
          when :lte
            attr_value && attr_value <= evaluated
          when :gt
            attr_value && attr_value > evaluated
          when :gte
            attr_value && attr_value >= evaluated
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
        raise AuthorizationUsageError, "Error occurred while validating attribute ##{attr} on #{object.inspect}: #{e}.\n" +
          "Please check your authorization rules and ensure the attribute is correctly spelled and \n" +
          "corresponds to a method on the model you are authorizing for."
      end
    end

    def deep_hash_clone (hash)
      hash.inject({}) do |memo, (key, val)|
        memo[key] = case val
                    when Hash
                      deep_hash_clone(val)
                    when NilClass, Symbol
                      val
                    else
                      val.clone
                    end
        memo
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

    def initialize_copy (from)
      @attr_hash = deep_hash_clone(@attr_hash) if @attr_hash.is_a?(Hash)
    end

    def validate? (attr_validator, object = nil, hash_or_attr = nil)
      object ||= attr_validator.object
      hash_or_attr ||= @attr_hash
      return false unless object

      case hash_or_attr
      when Symbol
        attr_value = object_attribute_value(object, hash_or_attr)
        case attr_value
        when nil
          raise NilAttributeValueError, "Attribute #{hash_or_attr.inspect} is nil in #{object.inspect}."
        when Enumerable
          attr_value.any? do |inner_value|
            attr_validator.engine.permit? @privilege, :object => inner_value, :user => attr_validator.user
          end
        else
          attr_validator.engine.permit? @privilege, :object => attr_value, :user => attr_validator.user
        end
      when Hash
        hash_or_attr.all? do |attr, sub_hash|
          attr_value = object_attribute_value(object, attr)
          if attr_value == nil
            raise NilAttributeValueError, "Attribute #{attr.inspect} is nil in #{object.inspect}."
          elsif attr_value.is_a?(Enumerable)
            attr_value.any? do |inner_value|
              validate?(attr_validator, inner_value, sub_hash)
            end
          else
            validate?(attr_validator, attr_value, sub_hash)
          end
        end
      when NilClass
        attr_validator.engine.permit? @privilege, :object => object, :user => attr_validator.user
      else
        raise AuthorizationError, "Wrong conditions hash format: #{hash_or_attr.inspect}"
      end
    end

    # may return an array of obligations to be OR'ed
    def obligation (attr_validator, hash_or_attr = nil, path = [])
      hash_or_attr ||= @attr_hash
      case hash_or_attr
      when Symbol
        @context ||= begin
          rule_model = attr_validator.context.to_s.classify.constantize
          context_reflection = self.class.reflection_for_path(rule_model, path + [hash_or_attr])
          if context_reflection.klass.respond_to?(:decl_auth_context)
            context_reflection.klass.decl_auth_context
          else
            context_reflection.klass.name.tableize.to_sym
          end
        rescue # missing model, reflections
          hash_or_attr.to_s.pluralize.to_sym
        end
        
        obligations = attr_validator.engine.obligations(@privilege,
                          :context => @context,
                          :user    => attr_validator.user)

        obligations.collect {|obl| {hash_or_attr => obl} }
      when Hash
        obligations_array_attrs = []
        obligations =
            hash_or_attr.inject({}) do |all, pair|
              attr, sub_hash = pair
              all[attr] = obligation(attr_validator, sub_hash, path + [attr])
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

    private
    def self.reflection_for_path (parent_model, path)
      reflection = path.empty? ? parent_model : begin
        parent = reflection_for_path(parent_model, path[0..-2])
        if !parent.respond_to?(:proxy_reflection) and parent.respond_to?(:klass)
          parent.klass.reflect_on_association(path.last)
        else
          parent.reflect_on_association(path.last)
        end
      rescue
        parent.reflect_on_association(path.last)
      end
      raise "invalid path #{path.inspect}" if reflection.nil?
      reflection
    end
  end
  
  # Represents a pseudo-user to facilitate anonymous users in applications
  class AnonymousUser
    attr_reader :role_symbols
    def initialize (roles = [Authorization.default_role])
      @role_symbols = roles
    end
  end
end

