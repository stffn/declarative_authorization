# Authorization::Reader

require File.dirname(__FILE__) + '/authorization.rb'

module Authorization
  # Parses an authorization configuration file in the authorization DSL and
  # constructs a data model of its contents.
  # 
  # For examples and the modelled data model, see the 
  # README[link:files/README.html].
  #
  # Also, see 
  # * AuthorizationRulesReader#role,
  # * AuthorizationRulesReader#includes,
  # * AuthorizationRulesReader#has_permission,
  # * AuthorizationRulesReader#on,
  # * AuthorizationRulesReader#to,
  # * AuthorizationRulesReader#if_attribute,
  # * PrivilegesReader#privilege and
  # * PrivilegesReader#includes
  # for details.
  #
  module Reader
    class ParameterError < Exception; end
    class DSLSyntaxError < Exception; end
    
    class DSLReader
      attr_reader :privileges_reader, :auth_rules_reader # :nodoc:

      def initialize ()
        @privileges_reader = PrivilegesReader.new
        @auth_rules_reader = AuthorizationRulesReader.new
      end

      def parse (dsl_data, file_name = nil)
        if file_name
          DSLMethods.new(self).instance_eval(dsl_data, file_name)
        else
          DSLMethods.new(self).instance_eval(dsl_data)
        end
      rescue SyntaxError, NoMethodError, NameError => e
        raise DSLSyntaxError, "Illegal DSL syntax: #{e}"
      end

      # TODO cache reader in production mode?
      def self.load (dsl_file)
        reader = new
        reader.parse(File.read(dsl_file), dsl_file)
        reader
      end

      # DSL methods
      class DSLMethods # :nodoc:
        def initialize (parent)
          @parent = parent
        end

        def privileges (&block)
          @parent.privileges_reader.instance_eval(&block)
        end

        def contexts (&block)
          # Not implemented
        end

        def authorization (&block)
          @parent.auth_rules_reader.instance_eval(&block)
        end
      end
    end

    # TODO handle privileges with separated context
    class PrivilegesReader
      attr_reader :privileges, :privilege_hierarchy # :nodoc:

      def initialize # :nodoc:
        @current_priv = nil
        @current_context = nil
        @privileges = []
        # {priv => [[priv,ctx], ...]}
        @privilege_hierarchy = {}
      end

      def append_privilege (priv) # :nodoc:
        @privileges << priv unless @privileges.include?(priv)
      end

      # Defines part of a privilege hierarchy.  For the given +privilege+,
      # included privileges may be defined in the block (through includes)
      # or as option :+includes+.  If the optional context is given,
      # the privilege hierarchy is limited to that context.
      #
      def privilege (privilege, context = nil, options = {}, &block)
        if context.is_a?(Hash)
          options = context
          context = nil
        end
        @current_priv = privilege
        @current_context = context
        append_privilege privilege
        instance_eval(&block) if block
        includes(*options[:includes]) if options[:includes]
      ensure
        @current_priv = nil
        @current_context = nil
      end

      # Specifies +privileges+ that are to be assigned as lower ones.
      def includes (*privileges)
        raise ParameterError, "includes only in privilege block" if @current_priv.nil?
        privileges.each do |priv|
          append_privilege priv
          @privilege_hierarchy[@current_priv] ||= []
          @privilege_hierarchy[@current_priv] << [priv, @current_context]
        end
      end
    end

    class AuthorizationRulesReader
      attr_reader :roles, :role_hierarchy, :auth_rules # :nodoc:

      def initialize # :nodoc:
        @current_role = nil
        @current_rule = nil
        @roles = []
        # higher_role => [lower_roles]
        @role_hierarchy = {}
        @auth_rules = []
      end

      def append_role (role) # :nodoc:
        @roles << role unless @roles.include? role
      end

      # Defines the authorization rules for the given +role+ in the
      # following block.
      def role (role, &block)
        append_role role
        @current_role = role
        yield
      ensure
        @current_role = nil
      end

      # Roles may inherit all the rights from subroles.  The given +roles+
      # become subroles of the current block's role.
      def includes (*roles)
        raise ParameterError, "includes only in role blocks" if @current_role.nil?
        @role_hierarchy[@current_role] ||= []
        @role_hierarchy[@current_role] += roles.flatten
      end
      
      # Allows the definition of privileges to be allowed for the current role,
      # either in a has_permission block or directly in has_permission.to.
      def has_permission_on (context, options = {}, &block)
        raise ParameterError, "has_permission_on only allowed in role blocks" if @current_role.nil?
        options = {:to => []}.merge(options)
        
        privs = options[:to] 
        privs = [privs] unless privs.is_a?(Array)
        raise ParameterError, "has_permission_on either needs a block or :to option" if !block_given? and privs.empty?
        
        rule = AuthorizationRule.new(@current_role, privs, context)
        @auth_rules << rule
        if block_given?
          @current_rule = rule
          yield
          # TODO ensure?
          @current_rule = nil
        end
      end
      
      # Used in a has_permission_on block, to may be used to specify privileges
      # to be assigned to the current role.
      def to (*privs)
        # in has_permission block
        raise ParameterError, "to only allowed in has_permission_on blocks" if @current_rule.nil?
        @current_rule.append_privileges(privs)
      end

      # In a has_permission block, if_attribute specifies additional conditions
      # of dynamic parameters that have to be met for the user to meet the
      # privileges in this block.  Multiple if_attribute statements are OR'ed.
      def if_attribute (attr_conditions_hash)
        raise ParameterError, "if_attribute only in has_permission blocks" if @current_rule.nil?
        parse_attribute_conditions_hash!(attr_conditions_hash)
        @current_rule.append_attribute Attribute.new(attr_conditions_hash)
      end
      
      # In an if_attribute statement, is says that the value has to be exactly
      # met by the if_attribute attribute.
      def is (&block)
        [:is, block]
      end
      
      # In an if_attribute statement, contains says that the value has to be
      # part of the collection specified by the if_attribute attribute.
      def contains (&block)
        [:contains, block]
      end
      
      private
      def parse_attribute_conditions_hash! (hash)
        merge_hash = {}
        hash.each do |key, value|
          if value.is_a?(Hash)
            parse_attribute_conditions_hash!(value)
          elsif !value.is_a?(Array)
            merge_hash[key] = [:is, lambda { value }]
          end
        end
        hash.merge!(merge_hash)
      end
    end
  end
end
