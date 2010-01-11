# Authorization::AuthorizationInController
require File.dirname(__FILE__) + '/authorization.rb'

module Authorization
  module AuthorizationInController
  
    def self.included(base) # :nodoc:
      base.extend(ClassMethods)
      base.hide_action :authorization_engine, :permitted_to?,
        :permitted_to!
    end
    
    DEFAULT_DENY = false
    
    # If attribute_check is set for filter_access_to, decl_auth will try to
    # load the appropriate object from the current controller's model with
    # the id from params[:id].  If that fails, a 404 Not Found is often the
    # right way to handle the error.  If you have additional measures in place
    # that restricts the find scope, handling this error as a permission denied
    # might be a better way.  Set failed_auto_loading_is_not_found to false
    # for the latter behaviour.
    @@failed_auto_loading_is_not_found = true
    def self.failed_auto_loading_is_not_found?
      @@failed_auto_loading_is_not_found
    end
    def self.failed_auto_loading_is_not_found= (new_value)
      @@failed_auto_loading_is_not_found = new_value
    end

    # Returns the Authorization::Engine for the current controller.
    def authorization_engine
      @authorization_engine ||= Authorization::Engine.instance
    end
    
    # If the current user meets the given privilege, permitted_to? returns true
    # and yields to the optional block.  The attribute checks that are defined
    # in the authorization rules are only evaluated if an object is given
    # for context.
    # 
    # See examples for Authorization::AuthorizationHelper #permitted_to?
    #
    # If no object or context is specified, the controller_name is used as
    # context.
    #
    def permitted_to? (privilege, object_or_sym = nil, options = {}, &block)
      permitted_to!(privilege, object_or_sym, options.merge(:non_bang => true), &block)
    end
    
    # Works similar to the permitted_to? method, but
    # throws the authorization exceptions, just like Engine#permit!
    def permitted_to! (privilege, object_or_sym = nil, options = {}, &block)
      context = object = nil
      if object_or_sym.nil?
        context = self.class.decl_auth_context
      elsif object_or_sym.is_a?(Symbol)
        context = object_or_sym
      else
        object = object_or_sym
      end

      non_bang = options.delete(:non_bang)
      args = [
        privilege,
        {:user => current_user,
         :object => object,
         :context => context,
         :skip_attribute_test => object.nil?}.merge(options)
      ]
      if non_bang
        authorization_engine.permit?(*args, &block)
      else
        authorization_engine.permit!(*args, &block)
      end
    end

    # While permitted_to? is used for authorization, in some cases
    # content should only be shown to some users without being concerned
    # with authorization.  E.g. to only show the most relevant menu options 
    # to a certain group of users.  That is what has_role? should be used for.
    def has_role? (*roles, &block)
      user_roles = authorization_engine.roles_for(current_user)
      result = roles.all? do |role|
        user_roles.include?(role)
      end
      yield if result and block_given?
      result
    end
    
    # As has_role? except checks all roles included in the role hierarchy
    def has_role_with_hierarchy?(*roles, &block)
      user_roles = authorization_engine.roles_with_hierarchy_for(current_user)
      result = roles.all? do |role|
        user_roles.include?(role)
      end
      yield if result and block_given?
      result
    end
    
    
    protected
    def filter_access_filter # :nodoc:
      permissions = self.class.all_filter_access_permissions
      all_permissions = permissions.select {|p| p.actions.include?(:all)}
      matching_permissions = permissions.select {|p| p.matches?(action_name)}
      allowed = false
      auth_exception = nil
      begin
        allowed = if !matching_permissions.empty?
                    matching_permissions.all? {|perm| perm.permit!(self)}
                  elsif !all_permissions.empty?
                    all_permissions.all? {|perm| perm.permit!(self)}
                  else
                    !DEFAULT_DENY
                  end
      rescue AuthorizationError => e
        auth_exception = e
      end

      unless allowed
        if all_permissions.empty? and matching_permissions.empty?
          logger.warn "Permission denied: No matching filter access " +
            "rule found for #{self.class.controller_name}.#{action_name}"
        elsif auth_exception
          logger.info "Permission denied: #{auth_exception}"
        end
        if respond_to?(:permission_denied)
          # permission_denied needs to render or redirect
          send(:permission_denied)
        else
          send(:render, :text => "You are not allowed to access this action.",
            :status => :forbidden)
        end
      end
    end

    def load_controller_object (context_without_namespace = nil) # :nodoc:
      instance_var = :"@#{context_without_namespace.to_s.singularize}"
      model = context_without_namespace.to_s.classify.constantize
      instance_variable_set(instance_var, model.find(params[:id]))
    end

    def load_parent_controller_object (parent_context_without_namespace) # :nodoc:
      instance_var = :"@#{parent_context_without_namespace.to_s.singularize}"
      model = parent_context_without_namespace.to_s.classify.constantize
      instance_variable_set(instance_var, model.find(params[:"#{parent_context_without_namespace.to_s.singularize}_id"]))
    end

    def new_controller_object_from_params (context_without_namespace, parent_context_without_namespace) # :nodoc:
      model_or_proxy = parent_context_without_namespace ?
           instance_variable_get(:"@#{parent_context_without_namespace.to_s.singularize}").send(context_without_namespace.to_sym) :
           context_without_namespace.to_s.classify.constantize
      instance_var = :"@#{context_without_namespace.to_s.singularize}"
      instance_variable_set(instance_var,
          model_or_proxy.new(params[context_without_namespace.to_s.singularize]))
    end

    def new_controller_object_for_collection (context_without_namespace, parent_context_without_namespace) # :nodoc:
      model_or_proxy = parent_context_without_namespace ?
           instance_variable_get(:"@#{parent_context_without_namespace.to_s.singularize}").send(context_without_namespace.to_sym) :
           context_without_namespace.to_s.classify.constantize
      instance_var = :"@#{context_without_namespace.to_s.singularize}"
      instance_variable_set(instance_var, model_or_proxy.new)
    end

    module ClassMethods
      #
      # Defines a filter to be applied according to the authorization of the
      # current user.  Requires at least one symbol corresponding to an
      # action as parameter.  The special symbol :+all+ refers to all action.
      # The all :+all+ statement is only employed if no specific statement is
      # present.
      #   class UserController < ApplicationController
      #     filter_access_to :index
      #     filter_access_to :new, :edit
      #     filter_access_to :all
      #     ...
      #   end
      # 
      # The default is to allow access unconditionally if no rule matches.
      # Thus, including the +filter_access_to+ :+all+ statement is a good
      # idea, implementing a default-deny policy.
      #   
      # When the access is denied, the method +permission_denied+ is called
      # on the current controller, if defined.  Else, a simple "you are not
      # allowed" string is output.  Log.info is given more information on the
      # reasons of denial.
      # 
      #   def permission_denied
      #     flash[:error] = 'Sorry, you are not allowed to the requested page.'
      #     respond_to do |format|
      #       format.html { redirect_to(:back) rescue redirect_to('/') }
      #       format.xml  { head :unauthorized }
      #       format.js   { head :unauthorized }
      #     end
      #   end
      # 
      # By default, required privileges are infered from the action name and
      # the controller name.  Thus, in UserController :+edit+ requires
      # :+edit+ +users+.  To specify required privilege, use the option :+require+
      #   filter_access_to :new, :create, :require => :create, :context => :users
      #
      # Without the :+attribute_check+ option, no constraints from the
      # authorization rules are enforced because for some actions (collections,
      # +new+, +create+), there is no object to evaluate conditions against.  To
      # allow attribute checks on all actions, it is a common pattern to provide
      # custom objects through +before_filters+:
      #   class BranchesController < ApplicationController
      #     before_filter :load_company
      #     before_filter :new_branch_from_company_and_params,
      #       :only => [:index, :new, :create]
      #     filter_access_to :all, :attribute_check => true
      #
      #     protected
      #     def new_branch_from_company_and_params
      #       @branch = @company.branches.new(params[:branch])
      #     end
      #   end
      # NOTE: +before_filters+ need to be defined before the first
      # +filter_access_to+ call.
      #   
      # For further customization, a custom filter expression may be formulated
      # in a block, which is then evaluated in the context of the controller
      # on a matching request.  That is, for checking two objects, use the 
      # following:
      #   filter_access_to :merge do
      #     permitted_to!(:update, User.find(params[:original_id])) and
      #       permitted_to!(:delete, User.find(params[:id]))
      #   end
      # The block should raise a Authorization::AuthorizationError or return
      # false if the access is to be denied.
      # 
      # Later calls to filter_access_to with overlapping actions overwrite
      # previous ones for that action.
      # 
      # All options:
      # [:+require+] 
      #   Privilege required; defaults to action_name
      # [:+context+] 
      #   The privilege's context, defaults to decl_auth_context, which consists
      #   of controller_name, prepended by any namespaces
      # [:+attribute_check+]
      #   Enables the check of attributes defined in the authorization rules.
      #   Defaults to false.  If enabled, filter_access_to will use a context
      #   object from one of the following sources (in that order):
      #   * the method from the :+load_method+ option,
      #   * an instance variable named after the singular of the context
      #     (by default from the controller name, e.g. @post for PostsController),
      #   * a find on the context model, using +params+[:id] as id value.
      #   Any of these methods will only be employed if :+attribute_check+
      #   is enabled.
      # [:+model+] 
      #   The data model to load a context object from.  Defaults to the
      #   context, singularized.
      # [:+load_method+]
      #   Specify a method by symbol or a Proc object which should be used 
      #   to load the object.  Both should return the loaded object.
      #   If a Proc object is given, e.g. by way of
      #   +lambda+, it is called in the instance of the controller.  
      #   Example demonstrating the default behaviour:
      #     filter_access_to :show, :attribute_check => true,
      #                      :load_method => lambda { User.find(params[:id]) }
      # 
      
      def filter_access_to (*args, &filter_block)
        options = args.last.is_a?(Hash) ? args.pop : {}
        options = {
          :require => nil,
          :context => nil,
          :attribute_check => false,
          :model => nil,
          :load_method => nil
        }.merge!(options)
        privilege = options[:require]
        context = options[:context]
        actions = args.flatten

        # collect permits in controller array for use in one before_filter
        unless filter_chain.any? {|filter| filter.method == :filter_access_filter}
          before_filter :filter_access_filter
        end
        
        filter_access_permissions.each do |perm|
          perm.remove_actions(actions)
        end
        filter_access_permissions << 
          ControllerPermission.new(actions, privilege, context,
                                   options[:attribute_check],
                                   options[:model],
                                   options[:load_method],
                                   filter_block)
      end
      
      # Collecting all the ControllerPermission objects from the controller
      # hierarchy.  Permissions for actions are overwritten by calls to 
      # filter_access_to in child controllers with the same action.
      def all_filter_access_permissions # :nodoc:
        ancestors.inject([]) do |perms, mod|
          if mod.respond_to?(:filter_access_permissions)
            perms + 
              mod.filter_access_permissions.collect do |p1| 
                p1.clone.remove_actions(perms.inject(Set.new) {|actions, p2| actions + p2.actions})
              end
          else
            perms
          end
        end
      end

      # To DRY up the filter_access_to statements in restful controllers,
      # filter_resource_access combines typical filter_access_to and
      # before_filter calls, which set up the instance variables.
      #
      # The simplest case are top-level resource controllers with only the
      # seven CRUD methods, e.g.
      #   class CompanyController < ApplicationController
      #     filter_resource_access
      #
      #     def index...
      #   end
      # Here, all CRUD actions are protected through a filter_access_to :all
      # statement.  :+attribute_check+ is enabled for all actions except for
      # the collection action :+index+.  To have an object for attribute checks
      # available, filter_resource_access will set the instance variable
      # @+company+ in before filters.  For the member actions (:+show+, :+edit+,
      # :+update+, :+destroy+) @company is set to Company.find(params[:id]).
      # For +new+ actions (:+new+, :+create+), filter_resource_access creates
      # a new object from company parameters: Company.new(params[:company].
      #
      # For nested resources, the parent object may be loaded automatically.
      #   class BranchController < ApplicationController
      #     filter_resource_access :nested_in => :companies
      #   end
      # Again, the CRUD actions are protected.  Now, for all CRUD actions,
      # the parent object @company is loaded from params[:company_id].  It is
      # also used when creating @branch for +new+ actions.  Here, attribute_check
      # is enabled for the collection :+index+ as well, checking attributes on a
      # @company.branches.new method.
      #
      # In many cases, the default seven CRUD actions are not sufficient.  As in
      # the resource definition for routing you may thus give additional member,
      # new and collection methods.  The options allow you to specify the
      # required privileges for each action by providing a hash or an array of
      # pairs.  By default, for each action the action name is taken as privilege
      # (action search in the example below requires the privilege :index
      # :companies).  Any controller action that is not specified and does not
      # belong to the seven CRUD actions is handled as a member method.
      #   class CompanyController < ApplicationController
      #     filter_resource_access :collection => [[:search, :index], :index],
      #         :additional_member => {:mark_as_key_company => :update}
      #   end
      # The +additional_+* options add to the respective CRUD actions,
      # the other options replace the respective CRUD actions.
      # 
      # You can override the default object loading by implementing any of the
      # following instance methods on the controller.  Examples are given for the
      # BranchController (with +nested_in+ set to :+companies+):
      # [+new_branch_from_params+]
      #   Used for +new+ actions.
      # [+new_branch_for_collection+]
      #   Used for +collection+ actions if the +nested_in+ option is set.
      # [+load_branch+]
      #   Used for +member+ actions.
      # [+load_company+]
      #   Used for all +new+, +member+, and +collection+ actions if the 
      #   +nested_in+ option is set.
      #
      # All options:
      # [:+member+]
      #   Member methods are actions like +show+, which have an params[:id] from
      #   which to load the controller object and assign it to @controller_name,
      #   e.g. @+branch+.
      #
      #   By default, member actions are [:+show+, :+edit+, :+update+,
      #   :+destroy+].  Also, any action not belonging to the seven CRUD actions
      #   are handled as member actions.
      #
      #   There are three different syntax to specify member, collection and
      #   new actions.
      #   * Hash:  Lets you set the required privilege for each action:
      #     {:+show+ => :+show+, :+mark_as_important+ => :+update+}
      #   * Array of actions or pairs: [:+show+, [:+mark_as_important+, :+update+]],
      #     with single actions requiring the privilege of the same name as the method.
      #   * Single method symbol: :+show+
      # [:+additional_member+]
      #   Allows to add additional member actions to the default resource +member+
      #   actions.
      # [:+collection+]
      #   Collection actions are like :+index+, actions without any controller object
      #   to check attributes of.  If +nested_in+ is given, a new object is
      #   created from the parent object, e.g. @company.branches.new.  Without
      #   +nested_in+, attribute check is deactivated for these actions.  By
      #   default, collection is set to :+index+.
      # [:+additional_collection+]
      #   Allows to add additional collaction actions to the default resource +collection+
      #   actions.
      # [:+new+]
      #   +new+ methods are actions such as +new+ and +create+, which don't
      #   receive a params[:id] to load an object from, but
      #   a params[:controller_name_singular] hash with attributes for a new
      #   object.  The attributes will be used here to create a new object and
      #   check the object against the authorization rules.  The object is
      #   assigned to @controller_name_singular, e.g. @branch.
      #
      #   If +nested_in+ is given, the new object
      #   is created from the parent_object.controller_name
      #   proxy, e.g. company.branches.new(params[:branch]).  By default,
      #   +new+ is set to [:new, :create].
      # [:+additional_new+]
      #   Allows to add additional new actions to the default resource +new+ actions.
      # [:+context+]
      #   The context is used to determine the model to load objects from for the
      #   before_filters and the context of privileges to use in authorization
      #   checks.
      # [:+nested_in+]
      #   Specifies the parent controller if the resource is nested in another
      #   one.  This is used to automatically load the parent object, e.g.
      #   @+company+ from params[:company_id] for a BranchController nested in
      #   a CompanyController.
      # [:+shallow+]
      #   Only relevant when used in conjunction with +nested_in+. Specifies a nested resource
      #   as being a shallow nested resource, resulting in the controller not attempting to
      #   load a parent object for all member actions defined by +member+ and
      #   +additional_member+ or rather the default member actions (:+show+, :+edit+,
      #   :+update+, :+destroy+).
      # [:+no_attribute_check+]
      #   Allows to set actions for which no attribute check should be perfomed.
      #   See filter_access_to on details.  By default, with no +nested_in+,
      #   +no_attribute_check+ is set to all collections.  If +nested_in+ is given
      #   +no_attribute_check+ is empty by default.
      #
      def filter_resource_access(options = {})
        options = {
          :new        => [:new, :create],
          :additional_new => nil,
          :member     => [:show, :edit, :update, :destroy],
          :additional_member => nil,
          :collection => [:index],
          :additional_collection => nil,
          #:new_method_for_collection => nil,  # only symbol method name
          #:new_method => nil,                 # only symbol method name
          #:load_method => nil,                # only symbol method name
          :no_attribute_check => nil,
          :context    => nil,
          :nested_in  => nil,
        }.merge(options)

        new_actions = actions_from_option(options[:new]).merge(
            actions_from_option(options[:additional_new]))
        members = actions_from_option(options[:member]).merge(
            actions_from_option(options[:additional_member]))
        collections = actions_from_option(options[:collection]).merge(
            actions_from_option(options[:additional_collection]))

        options[:no_attribute_check] ||= collections.keys unless options[:nested_in]

        unless options[:nested_in].blank?
          load_parent_method = :"load_#{options[:nested_in].to_s.singularize}"
          shallow_exceptions = options[:shallow] ? {:except => members.keys} : {}
          before_filter shallow_exceptions do |controller|
            if controller.respond_to?(load_parent_method)
              controller.send(load_parent_method)
            else
              controller.send(:load_parent_controller_object, options[:nested_in])
            end
          end

          new_for_collection_method = :"new_#{controller_name.singularize}_for_collection"
          before_filter :only => collections.keys do |controller|
            # new_for_collection
            if controller.respond_to?(new_for_collection_method)
              controller.send(new_for_collection_method)
            else
              controller.send(:new_controller_object_for_collection,
                  options[:context] || controller_name, options[:nested_in])
            end
          end
        end

        new_from_params_method = :"new_#{controller_name.singularize}_from_params"
        before_filter :only => new_actions.keys do |controller|
          # new_from_params
          if controller.respond_to?(new_from_params_method)
            controller.send(new_from_params_method)
          else
            controller.send(:new_controller_object_from_params,
                options[:context] || controller_name, options[:nested_in])
          end
        end
        load_method = :"load_#{controller_name.singularize}"
        before_filter :only => members.keys do |controller|
          # load controller object
          if controller.respond_to?(load_method)
            controller.send(load_method)
          else
            controller.send(:load_controller_object, options[:context] || controller_name)
          end
        end
        filter_access_to :all, :attribute_check => true, :context => options[:context]

        members.merge(new_actions).merge(collections).each do |action, privilege|
          if action != privilege or (options[:no_attribute_check] and options[:no_attribute_check].include?(action))
            filter_options = {
              :context          => options[:context],
              :attribute_check  => !options[:no_attribute_check] || !options[:no_attribute_check].include?(action)
            }
            filter_options[:require] = privilege if action != privilege
            filter_access_to(action, filter_options)
          end
        end
      end

      # Returns the context for authorization checks in the current controller.
      # Uses the controller_name and prepends any namespaces underscored and
      # joined with underscores.
      #
      # E.g.
      #   AllThosePeopleController         => :all_those_people
      #   AnyName::Space::ThingsController => :any_name_space_things
      #
      def decl_auth_context
        prefixes = name.split('::')[0..-2].map(&:underscore)
        ((prefixes + [controller_name]) * '_').to_sym
      end
      
      protected
      def filter_access_permissions # :nodoc:
        unless filter_access_permissions?
          ancestors[1..-1].reverse.each do |mod|
            mod.filter_access_permissions if mod.respond_to?(:filter_access_permissions)
          end
        end
        class_variable_set(:@@declarative_authorization_permissions, {}) unless filter_access_permissions?
        class_variable_get(:@@declarative_authorization_permissions)[self.name] ||= []
      end
      
      def filter_access_permissions? # :nodoc:
        class_variable_defined?(:@@declarative_authorization_permissions)
      end

      def actions_from_option (option) # :nodoc:
        case option
        when nil
          {}
        when Symbol, String
          {option.to_sym => option.to_sym}
        when Hash
          option
        when Enumerable
          option.each_with_object({}) do |action, hash|
            if action.is_a?(Array)
              raise "Unexpected option format: #{option.inspect}" if action.length != 2
              hash[action.first] = action.last
            else
              hash[action.to_sym] = action.to_sym
            end
          end
        end
      end
    end
  end
  
  class ControllerPermission # :nodoc:
    attr_reader :actions, :privilege, :context, :attribute_check
    def initialize (actions, privilege, context, attribute_check = false, 
                    load_object_model = nil, load_object_method = nil,
                    filter_block = nil)
      @actions = actions.to_set
      @privilege = privilege
      @context = context
      @load_object_model = load_object_model
      @load_object_method = load_object_method
      @filter_block = filter_block
      @attribute_check = attribute_check
    end
    
    def matches? (action_name)
      @actions.include?(action_name.to_sym)
    end
    
    def permit! (contr)
      if @filter_block
        return contr.instance_eval(&@filter_block)
      end
      object = @attribute_check ? load_object(contr) : nil
      privilege = @privilege || :"#{contr.action_name}"

      contr.authorization_engine.permit!(privilege, 
                                         :user => contr.send(:current_user),
                                         :object => object,
                                         :skip_attribute_test => !@attribute_check,
                                         :context => @context || contr.class.decl_auth_context)
    end
    
    def remove_actions (actions)
      @actions -= actions
      self
    end
    
    private
    def load_object(contr)
      if @load_object_method and @load_object_method.is_a?(Symbol)
        contr.send(@load_object_method)
      elsif @load_object_method and @load_object_method.is_a?(Proc)
        contr.instance_eval(&@load_object_method)
      else
        load_object_model = @load_object_model ||
            (@context ? @context.to_s.classify.constantize : contr.class.controller_name.classify.constantize)
        instance_var = :"@#{load_object_model.name.underscore}"
        object = contr.instance_variable_get(instance_var)
        unless object
          begin
            object = load_object_model.find(contr.params[:id])
          rescue RuntimeError => e
            contr.logger.debug("filter_access_to tried to find " +
                "#{load_object_model} from params[:id] " +
                "(#{contr.params[:id].inspect}), because attribute_check is enabled " +
                "and #{instance_var.to_s} isn't set, but failed: #{e.class.name}: #{e}")
            raise if AuthorizationInController.failed_auto_loading_is_not_found?
          end
          contr.instance_variable_set(instance_var, object)
        end
        object
      end
    end
  end
end
