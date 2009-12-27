# Authorization::Reader

require File.dirname(__FILE__) + '/authorization.rb'

module Authorization
  # Parses an authorization configuration file in the authorization DSL and
  # constructs a data model of its contents.
  # 
  # For examples and the modelled data model, see the 
  # README[link:files/README_rdoc.html].
  #
  # Also, see role definition methods
  # * AuthorizationRulesReader#role,
  # * AuthorizationRulesReader#includes,
  # * AuthorizationRulesReader#title,
  # * AuthorizationRulesReader#description
  #
  # Methods for rule definition in roles
  # * AuthorizationRulesReader#has_permission_on,
  # * AuthorizationRulesReader#to,
  # * AuthorizationRulesReader#if_attribute,
  # * AuthorizationRulesReader#if_permitted_to
  #
  # Methods to be used in if_attribute statements
  # * AuthorizationRulesReader#contains,
  # * AuthorizationRulesReader#does_not_contain,
  # * AuthorizationRulesReader#intersects_with,
  # * AuthorizationRulesReader#is,
  # * AuthorizationRulesReader#is_not,
  # * AuthorizationRulesReader#is_in,
  # * AuthorizationRulesReader#is_not_in
  #
  # And privilege definition methods
  # * PrivilegesReader#privilege,
  # * PrivilegesReader#includes
  #
  module Reader
    # Signals errors that occur while reading and parsing an authorization DSL
    class DSLError < Exception; end
    # Signals errors in the syntax of an authorization DSL.
    class DSLSyntaxError < DSLError; end
    
    # Top-level reader, parses the methods +privileges+ and +authorization+.
    # +authorization+ takes a block with authorization rules as described in
    # AuthorizationRulesReader.  The block to +privileges+ defines privilege
    # hierarchies, as described in PrivilegesReader.
    #
    class DSLReader
      attr_reader :privileges_reader, :auth_rules_reader # :nodoc:

      def initialize ()
        @privileges_reader = PrivilegesReader.new
        @auth_rules_reader = AuthorizationRulesReader.new
      end

      # Parses a authorization DSL specification from the string given
      # in +dsl_data+.  Raises DSLSyntaxError if errors occur on parsing.
      def parse (dsl_data, file_name = nil)
        if file_name
          DSLMethods.new(self).instance_eval(dsl_data, file_name)
        else
          DSLMethods.new(self).instance_eval(dsl_data)
        end
      rescue SyntaxError, NoMethodError, NameError => e
        raise DSLSyntaxError, "Illegal DSL syntax: #{e}"
      end

      # Loads and parses a DSL from the given file name.
      def self.load (dsl_files)
        # TODO cache reader in production mode?
        reader = new
        dsl_files = [dsl_files].flatten
        dsl_files.each do |file|
          reader.parse(File.read(file), file) if File.exist?(file)
        end
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

    # The PrivilegeReader handles the part of the authorization DSL in
    # a +privileges+ block.  Here, privilege hierarchies are defined.
    class PrivilegesReader
      # TODO handle privileges with separated context
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

      # Specifies +privileges+ that are to be assigned as lower ones.  Only to
      # be used inside a privilege block.
      def includes (*privileges)
        raise DSLError, "includes only in privilege block" if @current_priv.nil?
        privileges.each do |priv|
          append_privilege priv
          @privilege_hierarchy[@current_priv] ||= []
          @privilege_hierarchy[@current_priv] << [priv, @current_context]
        end
      end
    end

    class AuthorizationRulesReader
      attr_reader :roles, :role_hierarchy, :auth_rules,
        :role_descriptions, :role_titles # :nodoc:

      def initialize # :nodoc:
        @current_role = nil
        @current_rule = nil
        @roles = []
        # higher_role => [lower_roles]
        @role_hierarchy = {}
        @role_titles = {}
        @role_descriptions = {}
        @auth_rules = []
      end

      def append_role (role, options = {}) # :nodoc:
        @roles << role unless @roles.include? role
        @role_titles[role] = options[:title] if options[:title]
        @role_descriptions[role] = options[:description] if options[:description]
      end

      # Defines the authorization rules for the given +role+ in the
      # following block.
      #   role :admin do
      #     has_permissions_on ...
      #   end
      #
      def role (role, options = {}, &block)
        append_role role, options
        @current_role = role
        yield
      ensure
        @current_role = nil
      end

      # Roles may inherit all the rights from subroles.  The given +roles+
      # become subroles of the current block's role.
      #   role :admin do
      #     includes :user
      #     has_permission_on :employees, :to => [:update, :create]
      #   end
      #   role :user do
      #     has_permission_on :employees, :to => :read
      #   end
      #
      def includes (*roles)
        raise DSLError, "includes only in role blocks" if @current_role.nil?
        @role_hierarchy[@current_role] ||= []
        @role_hierarchy[@current_role] += roles.flatten
      end
      
      # Allows the definition of privileges to be allowed for the current role,
      # either in a has_permission_on block or directly in one call.
      #   role :admin
      #     has_permission_on :employees, :to => :read
      #     has_permission_on [:employees, :orders], :to => :read
      #     has_permission_on :employees do
      #       to :create
      #       if_attribute ...
      #     end
      #     has_permission_on :employees, :to => :delete do
      #       if_attribute ...
      #     end
      #   end
      # The block form allows to describe restrictions on the permissions
      # using if_attribute.  Multiple has_permission_on statements are
      # OR'ed when evaluating the permissions.  Also, multiple if_attribute
      # statements in one block are OR'ed if no :+join_by+ option is given
      # (see below).  To AND conditions, either set :+join_by+ to :and or place
      # them in one if_attribute statement.
      # 
      # Available options
      # [:+to+]
      #   A symbol or an array of symbols representing the privileges that
      #   should be granted in this statement.
      # [:+join_by+]
      #   Join operator to logically connect the constraint statements inside
      #   of the has_permission_on block.  May be :+and+ or :+or+.  Defaults to :+or+.
      #
      def has_permission_on (*args, &block)
        options = args.extract_options!
        context = args.flatten
        
        raise DSLError, "has_permission_on only allowed in role blocks" if @current_role.nil?
        options = {:to => [], :join_by => :or}.merge(options)
        
        privs = options[:to] 
        privs = [privs] unless privs.is_a?(Array)
        raise DSLError, "has_permission_on either needs a block or :to option" if !block_given? and privs.empty?

        file, line = file_and_line_number_from_call_stack
        rule = AuthorizationRule.new(@current_role, privs, context, options[:join_by],
                   :source_file => file, :source_line => line)
        @auth_rules << rule
        if block_given?
          @current_rule = rule
          yield
          raise DSLError, "has_permission_on block content specifies no privileges" if rule.privileges.empty?
          # TODO ensure?
          @current_rule = nil
        end
      end
      
      # Sets a description for the current role.  E.g.
      #   role :admin
      #     description "To be assigned to administrative personnel"
      #     has_permission_on ...
      #   end
      def description (text)
        raise DSLError, "description only allowed in role blocks" if @current_role.nil?
        role_descriptions[@current_role] = text
      end
      
      # Sets a human-readable title for the current role.  E.g.
      #   role :admin
      #     title "Administrator"
      #     has_permission_on ...
      #   end
      def title (text)
        raise DSLError, "title only allowed in role blocks" if @current_role.nil?
        role_titles[@current_role] = text
      end
      
      # Used in a has_permission_on block, to may be used to specify privileges
      # to be assigned to the current role under the conditions specified in
      # the current block.
      #   role :admin
      #     has_permission_on :employees do
      #       to :create, :read, :update, :delete
      #     end
      #   end
      def to (*privs)
        raise DSLError, "to only allowed in has_permission_on blocks" if @current_rule.nil?
        @current_rule.append_privileges(privs)
      end

      # In a has_permission_on block, if_attribute specifies conditions
      # of dynamic parameters that have to be met for the user to meet the
      # privileges in this block.  Conditions are evaluated on the context
      # object.  Thus, the following allows CRUD for branch admins only on 
      # employees that belong to the same branch as the current user.
      #   role :branch_admin
      #     has_permission_on :employees do
      #       to :create, :read, :update, :delete
      #       if_attribute :branch => is { user.branch }
      #     end
      #   end
      # In this case, is is the operator for evaluating the condition.  Another
      # operator is contains for collections.  In the block supplied to the
      # operator, +user+ specifies the current user for whom the condition
      # is evaluated.
      # 
      # Conditions may be nested:
      #   role :company_admin
      #     has_permission_on :employees do
      #       to :create, :read, :update, :delete
      #       if_attribute :branch => { :company => is {user.branch.company} }
      #     end
      #   end
      #
      # has_many and has_many through associations may also be nested.
      # Then, at least one item in the association needs to fulfill the
      # subsequent condition:
      #   if_attribute :company => { :branches => { :manager => { :last_name => is { user.last_name } } }
      # Beware of possible performance issues when using has_many associations in
      # permitted_to? checks.  For
      #   permitted_to? :read, object
      # a check like
      #   object.company.branches.any? { |branch| branch.manager ... }
      # will be executed.  with_permission_to scopes construct efficient SQL
      # joins, though.
      # 
      # Multiple attributes in one :if_attribute statement are AND'ed.
      # Multiple if_attribute statements are OR'ed if the join operator for the
      # has_permission_on block isn't explicitly set.  Thus, the following would
      # require the current user either to be of the same branch AND the employee
      # to be "changeable_by_coworker".  OR the current user has to be the
      # employee in question.
      #   has_permission_on :employees, :to => :manage do
      #     if_attribute :branch => is {user.branch}, :changeable_by_coworker => true
      #     if_attribute :id => is {user.id}
      #   end
      # The join operator for if_attribute rules can explicitly set to AND, though.
      # See has_permission_on for details.
      #
      # Arrays and fixed values may be used directly as hash values:
      #   if_attribute :id   => 1
      #   if_attribute :type => "special"
      #   if_attribute :id   => [1,2]
      #
      def if_attribute (attr_conditions_hash)
        raise DSLError, "if_attribute only in has_permission blocks" if @current_rule.nil?
        parse_attribute_conditions_hash!(attr_conditions_hash)
        @current_rule.append_attribute Attribute.new(attr_conditions_hash)
      end

      # if_permitted_to allows the has_permission_on block to depend on
      # permissions on associated objects.  By using it, the authorization
      # rules may be a lot DRYer.  E.g.:
      #
      #   role :branch_manager
      #     has_permission_on :branches, :to => :manage do
      #       if_attribute :employees => includes { user }
      #     end
      #     has_permission_on :employees, :to => :read do
      #       if_permitted_to :read, :branch
      #       # instead of
      #       # if_attribute :branch => { :employees => includes { user } }
      #     end
      #   end
      #
      # if_permitted_to associations may be nested as well:
      #   if_permitted_to :read, :branch => :company
      #
      # You can even use has_many associations as target.  Then, it is checked
      # if the current user has the required privilege on *any* of the target objects.
      #   if_permitted_to :read, :branch => :employees
      # Beware of performance issues with permission checks.  In the current implementation,
      # all employees are checked until the first permitted is found.
      # with_permissions_to, on the other hand, constructs more efficient SQL
      # instead.
      #
      # To check permissions based on the current object, the attribute has to
      # be left out:
      #   has_permission_on :branches, :to => :manage do
      #     if_attribute :employees => includes { user }
      #   end
      #   has_permission_on :branches, :to => :paint_green do
      #     if_permitted_to :update
      #   end
      # Normally, one would merge those rules into one.  Deviding makes sense
      # if additional if_attribute are used in the second rule or those rules
      # are applied to different roles.
      #
      # Options:
      # [:+context+]
      #   When using with_permissions_to, the target context of the if_permitted_to
      #   statement is infered from the last reflections target class.  Still,
      #   you may override this algorithm by setting the context explicitly.
      #     if_permitted_to :read, :home_branch, :context => :branches
      #     if_permitted_to :read, :branch => :main_company, :context => :companies
      #
      def if_permitted_to (privilege, attr_or_hash = nil, options = {})
        raise DSLError, "if_permitted_to only in has_permission blocks" if @current_rule.nil?
        options[:context] ||= attr_or_hash.delete(:context) if attr_or_hash.is_a?(Hash)
        # only :context option in attr_or_hash:
        attr_or_hash = nil if attr_or_hash.is_a?(Hash) and attr_or_hash.empty?
        @current_rule.append_attribute AttributeWithPermission.new(privilege,
            attr_or_hash, options[:context])
      end
      
      # In an if_attribute statement, is says that the value has to be
      # met exactly by the if_attribute attribute.  For information on the block
      # argument, see if_attribute.
      def is (&block)
        [:is, block]
      end

      # The negation of is.
      def is_not (&block)
        [:is_not, block]
      end

      # In an if_attribute statement, contains says that the value has to be
      # part of the collection specified by the if_attribute attribute.
      # For information on the block argument, see if_attribute.
      def contains (&block)
        [:contains, block]
      end

      # The negation of contains.  Currently, query rewriting is disabled
      # for does_not_contain.
      def does_not_contain (&block)
        [:does_not_contain, block]
      end

      # In an if_attribute statement, intersects_with requires that at least
      # one of the values has to be part of the collection specified by the
      # if_attribute attribute.  The value block needs to evaluate to an
      # Enumerable.  For information on the block argument, see if_attribute.
      def intersects_with (&block)
        [:intersects_with, block]
      end
      
      # In an if_attribute statement, is_in says that the value has to
      # contain the attribute value.
      # For information on the block argument, see if_attribute.
      def is_in (&block)
        [:is_in, block]
      end

      # The negation of is_in.
      def is_not_in (&block)
        [:is_not_in, block]
      end
      
      private
      def parse_attribute_conditions_hash! (hash)
        merge_hash = {}
        hash.each do |key, value|
          if value.is_a?(Hash)
            parse_attribute_conditions_hash!(value)
          elsif !value.is_a?(Array)
            merge_hash[key] = [:is, lambda { value }]
          elsif value.is_a?(Array) and !value[0].is_a?(Symbol)
            merge_hash[key] = [:is_in, lambda { value }]
          end
        end
        hash.merge!(merge_hash)
      end
      
      def file_and_line_number_from_call_stack
        caller_parts = caller(2).first.split(':')
        [caller_parts[0] == "(eval)" ? nil : caller_parts[0],
          caller_parts[1] && caller_parts[1].to_i]
      end
    end
  end
end
