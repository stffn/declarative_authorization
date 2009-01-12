# Authorization::Maintenance
require File.dirname(__FILE__) + '/authorization.rb'

module Authorization
  
  def self.ignore_access_control (state = nil) # :nodoc:
    @@ignore_access_control = state unless state.nil?
    @@ignore_access_control
  end
  
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
    def without_access_control
      Authorization.ignore_access_control(true)
      yield
    ensure
      Authorization.ignore_access_control(false)
    end

    # A class method variant of without_access_control.  Thus, one can call
    #  Authorization::Maintenance::without_access_control do
    #    ...
    #  end
    def self.without_access_control
      Authorization.ignore_access_control(true)
      yield
    ensure
      Authorization.ignore_access_control(false)
    end

    # Sets the current user for the declarative authorization plugin to the
    # given one for the execution of the supplied block.  Suitable for tests
    # on certain users.
    def with_user (user)
      prev_user = Authorization.current_user
      Authorization.current_user = user
      yield
    ensure
      Authorization.current_user = prev_user
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
  module TestHelper
    include Authorization::Maintenance
    
    # Analogue to the Ruby's assert_raise method, only executing the block
    # in the context of the given user.
    def assert_raise_with_user (user, *args, &block)
      assert_raise(*args) do
        with_user(user, &block)
      end
    end
    
    def request_with (user, method, xhr, action, params = {}, 
        session = {}, flash = {})
      session = session.merge({:user => user})
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
