require File.join(File.dirname(__FILE__), 'test_helper.rb')
require File.dirname(__FILE__) + '/../lib/in_controller.rb'

MockController.send :include, Authorization::AuthorizationInController

class LoadMockObject < MockDataObject
  def self.find(*args)
    new :id => args[0]
  end
end
class SpecificMockController < MockController
  filter_access_to :test_action, :require => :test, :context => :permissions
  filter_access_to :test_action_2, :require => :test, :context => :permissions_2
  filter_access_to :show
  filter_access_to :edit, :create, :require => :test, :context => :permissions
  filter_access_to :edit_2, :require => :test, :context => :permissions,
    :attribute_check => true, :model => LoadMockObject
  filter_access_to :new, :require => :test, :context => :permissions
end

class AllMockController < MockController
  filter_access_to :all
  filter_access_to :view, :require => :test, :context => :permissions
  action_methods :show, :view
end

class LoadObjectMockController < MockController
  filter_access_to :show, :attribute_check => true, :model => LoadMockObject
  filter_access_to :edit, :attribute_check => true
  filter_access_to :update, :delete, :attribute_check => true,
                   :load_method => lambda {MockDataObject.new(:test => 1)}
  filter_access_to :create do
    authorization_engine.permit!(:edit, :context => :load_mock_objects,
      :user => current_user)
  end
  filter_access_to :view, :attribute_check => true, :load_method => :load_method
  def self.controller_name
    "load_mock_objects"
  end
  def load_method
    MockDataObject.new(:test => 2)
  end
end

class AccessOverwriteController < MockController
  filter_access_to :test_action, :test_action_2, 
    :require => :test, :context => :permissions_2
  filter_access_to :test_action, :require => :test, :context => :permissions
end

class PeopleController < MockController
  filter_access_to :all
  action_methods :show
  def self.controller_name
    "people"
  end
end

class CommonController < MockController
  filter_access_to :delete, :context => :common
  filter_access_to :all
end
class CommonChild1Controller < CommonController
  filter_access_to :all, :context => :context_1
end
class CommonChild2Controller < CommonController
  filter_access_to :delete
  action_methods :show
end


class ControllerTest < Test::Unit::TestCase
  
  def test_filter_access
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test
          has_permission_on :mocks, :to => :show
        end
      end
    }
    controller = SpecificMockController.new(reader)
    assert !controller.before_filters.empty?
    
    controller.request!(MockUser.new(:test_role), "test_action")
    assert !controller.called_render
    
    controller.request!(MockUser.new(:test_role), "test_action_2")
    assert controller.called_render
    
    controller.request!(MockUser.new(:test_role_2), "test_action")
    assert controller.called_render
    
    controller.request!(MockUser.new(:test_role), "show")
    assert !controller.called_render
  end
  
  def test_filter_access_multi_actions
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test
        end
      end
    }
    controller = SpecificMockController.new(reader)    
    controller.request!(MockUser.new(:test_role), "create")
    assert !controller.called_render
  end
  
  def test_filter_access_unprotected_actions
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
        end
      end
    }
    controller = SpecificMockController.new(reader)
    controller.request!(MockUser.new(:test_role), "unprotected_action")
    assert !controller.called_render
  end

  def test_filter_access_priv_hierarchy
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      privileges do
        privilege :read do
          includes :list, :show
        end
      end
      authorization do
        role :test_role do
          has_permission_on :mocks, :to => :read
        end
      end
    }
    controller = SpecificMockController.new(reader)    
    controller.request!(MockUser.new(:test_role), "show")
    assert !controller.called_render
  end
  
  def test_filter_access_skip_attribute_test
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :id => is { user }
          end
        end
      end
    }
    controller = SpecificMockController.new(reader)    
    controller.request!(MockUser.new(:test_role), "new")
    assert !controller.called_render
    
    controller.request!(MockUser.new(:test_role), "edit_2")
    assert controller.called_render
  end

  def test_filter_access_all
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test
          has_permission_on :mocks, :to => :show
        end
      end
    }
    
    controller = AllMockController.new(reader)
    
    controller.request!(MockUser.new(:test_role), "show")
    assert !controller.called_render
    
    controller.request!(MockUser.new(:test_role), "view")
    assert !controller.called_render
    
    controller.request!(MockUser.new(:test_role_2), "show")
    assert controller.called_render
  end
  
  def test_filter_access_with_object_load
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :load_mock_objects, :to => [:show, :edit] do
            if_attribute :id => is {1}
          end
        end
      end
    }
    
    controller = LoadObjectMockController.new(reader)
    controller.request!(MockUser.new(:test_role), "show", :id => 2)
    assert controller.called_render
    
    controller = LoadObjectMockController.new(reader)
    controller.request!(MockUser.new(:test_role), "show", :id => 1)
    assert !controller.called_render
    
    controller = LoadObjectMockController.new(reader)
    controller.request!(MockUser.new(:test_role), "edit", :id => 1)
    assert !controller.called_render
    assert controller.instance_variable_defined?(:@load_mock_object)
  end
  
  def test_filter_access_with_object_load_custom
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :load_mock_objects, :to => :view do
            if_attribute :test => is {2}
          end
          has_permission_on :load_mock_objects, :to => :update do
            if_attribute :test => is {1}
          end
          has_permission_on :load_mock_objects, :to => :delete do
            if_attribute :test => is {2}
          end
        end
      end
    }
    
    controller = LoadObjectMockController.new(reader)
    controller.request!(MockUser.new(:test_role), "delete")
    assert controller.called_render
    
    controller = LoadObjectMockController.new(reader)
    controller.request!(MockUser.new(:test_role), "view")
    assert !controller.called_render
    
    controller = LoadObjectMockController.new(reader)
    controller.request!(MockUser.new(:test_role), "update")
    assert !controller.called_render
  end
  
  def test_filter_access_custom
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :load_mock_objects, :to => :edit
        end
        role :test_role_2 do
          has_permission_on :load_mock_objects, :to => :create
        end
      end
    }
    
    controller = LoadObjectMockController.new(reader)
    controller.request!(MockUser.new(:test_role), "create")
    assert !controller.called_render
    
    controller = LoadObjectMockController.new(reader)
    controller.request!(MockUser.new(:test_role_2), "create")
    assert controller.called_render
  end
  
  def test_filter_access_overwrite
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test
        end
      end
    }
    controller = AccessOverwriteController.new(reader)
    controller.request!(MockUser.new(:test_role), "test_action_2")
    assert controller.called_render
    
    controller.request!(MockUser.new(:test_role), "test_action")
    assert !controller.called_render
  end
  
  def test_filter_access_people_controller
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :people, :to => :show
        end
      end
    }
    controller = PeopleController.new(reader)
    controller.request!(MockUser.new(:test_role), "show")
    assert !controller.called_render
  end
  
  def test_controller_hierarchy
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :mocks, :to => [:delete, :show]
        end
      end
    }
    controller = CommonChild2Controller.new(reader)
    #p controller.class.send(:class_variable_get, :@@permissions)
    controller.request!(MockUser.new(:test_role), "show")
    assert !controller.called_render
    controller.request!(MockUser.new(:test_role), "delete")
    assert !controller.called_render
  end
end
