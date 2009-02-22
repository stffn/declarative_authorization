# Authorization::AuthorizationInModel
require File.dirname(__FILE__) + '/authorization.rb'
require File.dirname(__FILE__) + '/obligation_scope.rb'

module Authorization
  
  module AuthorizationInModel
    
    def self.included(base) # :nodoc:
      #base.extend(ClassMethods)
      base.module_eval do
        scopes[:with_permissions_to] = lambda do |parent_scope, *args|
          options = args.last.is_a?(Hash) ? args.pop : {}
          privilege = (args[0] || :read).to_sym
          privileges = [privilege]
          context = options[:context] || :"#{parent_scope.table_name}"
          
          user = options[:user] || Authorization.current_user

          engine = Authorization::Engine.instance
          engine.permit!(privileges, :user => user, :skip_attribute_test => true,
                         :context => context)

          obligation_scope_for( privileges, :user => user,
              :context => context, :engine => engine, :model => parent_scope)
        end
        
        # Builds and returns a scope with joins and conditions satisfying all obligations.
        def self.obligation_scope_for( privileges, options = {} )
          options = {
            :user => Authorization.current_user,
            :context => nil,
            :model => self,
            :engine => nil,
          }.merge(options)
          engine ||= Authorization::Engine.instance

          scope = ObligationScope.new( options[:model], {} )
          engine.obligations( privileges, :user => options[:user], :context => options[:context] ).each do |obligation|
            scope.parse!( obligation )
          end
          scope
        end

        # Named scope for limiting query results according to the authorization
        # of the current user.  If no privilege is given, :+read+ is assumed.
        # 
        #   User.with_permissions_to
        #   User.with_permissions_to(:update)
        #   User.with_permissions_to(:update, :context => :users)
        #   
        # As in the case of other named scopes, this one may be chained:
        #   User.with_permission_to.find(:all, :conditions...)
        # 
        # Options
        # [:+context+]
        #   Context for the privilege to be evaluated in; defaults to the
        #   model's table name.
        # [:+user+]
        #   User to be used for gathering obligations; defaults to the
        #   current user.
        #
        def self.with_permissions_to (*args)
          scopes[:with_permissions_to].call(self, *args)
        end
        
        # Activates model security for the current model.  Then, CRUD operations
        # are checked against the authorization of the current user.  The
        # privileges are :+create+, :+read+, :+update+ and :+delete+ in the
        # context of the model.  By default, :+read+ is not checked because of
        # performance impacts, especially with large result sets.
        # 
        #   class User < ActiveRecord::Base
        #     using_access_control
        #   end
        #   
        # If an operation is not permitted, a Authorization::AuthorizationError
        # is raised.
        # 
        # Available options
        # [:+context+] Specify context different from the models table name.
        # [:+include_read+] Also check for :+read+ privilege after find.
        #
        def self.using_access_control (options = {})
          options = {
            :context => nil,
            :include_read => false
          }.merge(options)
          context = (options[:context] || self.table_name).to_sym

          class_eval do
            before_create do |object|
              Authorization::Engine.instance.permit!(:create, :object => object,
                :context => context)
            end
            
            before_update do |object|
              Authorization::Engine.instance.permit!(:update, :object => object,
                :context => context)
            end
            
            before_destroy do |object|
              Authorization::Engine.instance.permit!(:delete, :object => object,
                :context => context)
            end
            
            # only called if after_find is implemented
            after_find do |object|
              Authorization::Engine.instance.permit!(:read, :object => object,
                :context => context)
            end
            
            if options[:include_read]
              def after_find; end
            end

            def self.using_access_control?
              true
            end
          end
        end

        # Returns true if the model is using model security.
        def self.using_access_control?
          false
        end
      end
    end
  end
end
