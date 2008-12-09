# Authorization::AuthorizationInModel
require File.dirname(__FILE__) + '/authorization.rb'

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

          scope_options = obligation_conditions(privileges, :user => user,
            :context => context, :engine => engine, :model => parent_scope)
          
          ActiveRecord::NamedScope::Scope.new(parent_scope, scope_options)
        end
        
        # Provides an conditions hash as expected by find with conditions
        # matching the obligations for the given privilege, context and 
        # user.
        # 
        # Options:
        # [:+user+] 
        #   User to create the obligations for, defaults to 
        #   Authorization.current_user
        # [:+context+] The privilege's context
        # [:+model+] 
        #   Model that the obligations should be applied on,
        #   defaults to self.
        # [:+engine+] 
        #   Authorization::Engine to be used for checks, defaults to
        #   Authorization::Engine.instance.
        #
        def self.obligation_conditions (privileges, options = {})
          options = {
            :user => Authorization.current_user,
            :context => nil,
            :model => self,
            :engine => nil,
          }.merge(options)
          engine ||= Authorization::Engine.instance
          
          conditions = []
          condition_values = []
          joins = Set.new

          engine.obligations(privileges, :user => options[:user], 
                             :context => options[:context]).each do |obligation|
            and_conditions = []
            obligation_conditions!(nil, obligation, options[:model], 
                                   and_conditions, condition_values, joins)
            and_conditions << connection.quote("1") if and_conditions.empty?
            conditions << and_conditions.collect {|c| "#{c}"} * ' AND ' unless and_conditions.empty?
          end

          scope_options = {}
          unless conditions.empty?
            scope_options[:select] = "#{connection.quote_table_name(options[:context])}.*" if options[:context]
            scope_options[:conditions] = [conditions.collect {|c| "(#{c})"} * ' OR '] + condition_values
            scope_options[:joins] = joins.to_a unless joins.empty?
          end
          scope_options
        end
        
        def self.obligation_conditions!(object_attribute, value, model, and_conditions,
                                        condition_values, joins) # :nodoc:
          if value.is_a?(Hash)
            value.each do |object_attr, operator_val|
              joins << object_attribute if object_attribute
              assoc_model = object_attribute ? model.reflect_on_association(object_attribute).klass : model
              obligation_conditions!(object_attr, operator_val, assoc_model, 
                                     and_conditions, condition_values, joins)
            end
          elsif value.is_a?(Array) and value.length == 2
            operator, value = value
            
            case operator
            when :contains
              # contains: {:test_models => [:contains, obj]} <=>
              #           {:test_models => {:id => [:is, obj.id]}}
              obligation_conditions!(object_attribute, {:id => [:is, value.id]}, model,
                                     and_conditions, condition_values, joins)
            when :is, :is_in
              id_obj_attr = :"#{object_attribute}_id"
              sql_operator = (operator == :is ? '= ?' : 'IN (?)')
              if model.columns_hash[id_obj_attr.to_s] or
                  model.columns_hash[object_attribute.to_s]
                if model.columns_hash[id_obj_attr.to_s]
                  and_conditions << "#{connection.quote_table_name(model.table_name)}.#{id_obj_attr} #{sql_operator}"
                else
                  and_conditions << "#{connection.quote_table_name(model.table_name)}.#{object_attribute} #{sql_operator}"
                end
                condition_values << if value.is_a?(ActiveRecord::Base)
                                      value.id
                                    elsif value.is_a?(Array) and value[0].is_a?(ActiveRecord::Base)
                                      value.map(&:id)
                                    else
                                      value
                                    end
              elsif operator == :is
                # seems to be a has_one association, so we reverse the condition
                obligation_conditions!(object_attribute, {:id => [:is, value.id]}, model,
                                       and_conditions, condition_values, joins)
              else
                raise AuthorizationError, "Operator #{operator.inspect} not supported with has_many attribute."
              end
            else
              raise AuthorizationError, "Unknown operator #{operator.inspect}"
            end
          else
            raise AuthorizationError, "Unexpected value element: #{value.inspect}"
          end
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
          end
        end
      end
    end

  end
end
