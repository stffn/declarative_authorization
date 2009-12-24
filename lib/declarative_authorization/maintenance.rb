# Authorization::Maintenance
require File.dirname(__FILE__) + '/authorization.rb'

module Authorization
  # Provides a few maintenance methods for modifying data without enforcing
  # authorization.
  module Maintenance
    # Disables access control for the given block.  Appropriate for
    # maintenance operation at the Rails console or in test case setup.
    # 
    # For use in the Rails console:
    #  require "vendor/plugins/declarative_authorization/lib/maintenance"
    #  include Authorization::Maintenance
    #
    #  without_access_control do
    #    SomeModel.find(:first).save
    #  end
    def without_access_control (&block)
      Authorization::Maintenance.without_access_control(&block)
    end

    # A class method variant of without_access_control.  Thus, one can call
    #  Authorization::Maintenance::without_access_control do
    #    ...
    #  end
    def self.without_access_control
      previous_state = Authorization.ignore_access_control
      begin
        Authorization.ignore_access_control(true)
        yield
      ensure
        Authorization.ignore_access_control(previous_state)
      end
    end

    # Sets the current user for the declarative authorization plugin to the
    # given one for the execution of the supplied block.  Suitable for tests
    # on certain users.
    def with_user (user, &block)
      Authorization::Maintenance.with_user(user, &block)
    end

    def self.with_user (user)
      prev_user = Authorization.current_user
      Authorization.current_user = user
      yield
    ensure
      Authorization.current_user = prev_user
    end

    # Module for grouping usage-related helper methods
    module Usage
      # Delivers a hash of {ControllerClass => usage_info_hash},
      # where usage_info_hash has the form of
      def self.usages_by_controller
        # load each application controller
        begin
          Dir.foreach(File.join(RAILS_ROOT, %w{app controllers})) do |entry|
            if entry =~ /^\w+_controller\.rb$/
              require File.join(RAILS_ROOT, %w{app controllers}, entry)
            end
          end
        rescue Errno::ENOENT
        end
        controllers = []
        ObjectSpace.each_object(Class) do |obj|
          controllers << obj if obj.ancestors.include?(ActionController::Base) and
                                !%w{ActionController::Base ApplicationController}.include?(obj.name)
        end

        controllers.inject({}) do |memo, controller|
          catchall_permissions = []
          permission_by_action = {}
          controller.all_filter_access_permissions.each do |controller_permissions|
            catchall_permissions << controller_permissions if controller_permissions.actions.include?(:all)
            controller_permissions.actions.reject {|action| action == :all}.each do |action|
              permission_by_action[action] = controller_permissions
            end
          end

          actions = controller.public_instance_methods(false) - controller.hidden_actions
          memo[controller] = actions.inject({}) do |actions_memo, action|
            action_sym = action.to_sym
            actions_memo[action_sym] =
              if permission_by_action[action_sym]
                {
                  :privilege => permission_by_action[action_sym].privilege,
                  :context   => permission_by_action[action_sym].context,
                  :controller_permissions => [permission_by_action[action_sym]]
                }
              elsif !catchall_permissions.empty?
                {
                  :privilege => catchall_permissions[0].privilege,
                  :context   => catchall_permissions[0].context,
                  :controller_permissions => catchall_permissions
                }
              else
                {}
              end
            actions_memo
          end
          memo
        end
      end
    end
  end
  
  # TestHelper provides assert methods and controller request methods which
  # take authorization into account and set the current user to a specific
  # one.
  #
  # Defines get_with, post_with, get_by_xhr_with etc. for methods 
  # get, post, put, delete each with the signature
  #   get_with(user, action, params = {}, session = {}, flash = {})
  #
  # Use it by including it in your TestHelper:
  #  require File.expand_path(File.dirname(__FILE__) + 
  #    "/../vendor/plugins/declarative_authorization/lib/maintenance")
  #  class Test::Unit::TestCase 
  #    include Authorization::TestHelper
  #    ...
  #    
  #    def admin
  #      # create admin user
  #    end
  #  end
  # 
  #  class SomeControllerTest < ActionController::TestCase
  #    def test_should_get_index
  #      ...
  #      get_with admin, :index, :param_1 => "param value"
  #      ...
  #    end
  #  end
  #
  # Note: get_with etc. do two things to set the user for the request:
  # Authorization.current_user is set and session[:user], session[:user_id]
  # are set appropriately.  If you determine the current user in a different
  # way, these methods might not work for you.
  module TestHelper
    include Authorization::Maintenance
    
    # Analogue to the Ruby's assert_raise method, only executing the block
    # in the context of the given user.
    def assert_raise_with_user (user, *args, &block)
      assert_raise(*args) do
        with_user(user, &block)
      end
    end

    # Test helper to test authorization rules.  E.g.
    #   with_user a_normal_user do
    #     should_not_be_allowed_to :update, :conferences
    #     should_not_be_allowed_to :read, an_unpublished_conference
    #     should_be_allowed_to :read, a_published_conference
    #   end
    def should_be_allowed_to (privilege, object_or_context)
      options = {}
      options[object_or_context.is_a?(Symbol) ? :context : :object] = object_or_context
      assert_nothing_raised do
        Authorization::Engine.instance.permit!(privilege, options)
      end
    end

    # See should_be_allowed_to
    def should_not_be_allowed_to (privilege, object_or_context)
      options = {}
      options[object_or_context.is_a?(Symbol) ? :context : :object] = object_or_context
      assert !Authorization::Engine.instance.permit?(privilege, options)
    end
    
    def request_with (user, method, xhr, action, params = {}, 
        session = {}, flash = {})
      session = session.merge({:user => user, :user_id => user.id})
      with_user(user) do
        if xhr
          xhr method, action, params, session, flash
        else
          send method, action, params, session, flash
        end
      end
    end
  
    def self.included (base)
      [:get, :post, :put, :delete].each do |method|
        base.class_eval <<-EOV, __FILE__, __LINE__
          def #{method}_with (user, *args)
            request_with(user, #{method.inspect}, false, *args)
          end

          def #{method}_by_xhr_with (user, *args)
            request_with(user, #{method.inspect}, true, *args)
          end
        EOV
      end
    end
  end
end
