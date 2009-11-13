require File.join(File.dirname(__FILE__), 'test_helper.rb')


class LoadMockObject < MockDataObject
  def self.name
    "LoadMockObject"
  end
end

##################
class SpecificMocksController < MocksController
  filter_access_to :test_action, :require => :test, :context => :permissions
  filter_access_to :test_action_2, :require => :test, :context => :permissions_2
  filter_access_to :show
  filter_access_to :edit, :create, :require => :test, :context => :permissions
  filter_access_to :edit_2, :require => :test, :context => :permissions,
    :attribute_check => true, :model => LoadMockObject
  filter_access_to :new, :require => :test, :context => :permissions
  
  filter_access_to [:action_group_action_1, :action_group_action_2]
  define_action_methods :test_action, :test_action_2, :show, :edit, :create,
    :edit_2, :new, :unprotected_action, :action_group_action_1, :action_group_action_2
end

class BasicControllerTest < ActionController::TestCase
  tests SpecificMocksController
  
  def test_filter_access_to_receiving_an_explicit_array
    reader = Authorization::Reader::DSLReader.new

    reader.parse %{
      authorization do
        role :test_action_group_2 do
          has_permission_on :specific_mocks, :to => :action_group_action_2
        end
      end
    }

    request!(MockUser.new(:test_action_group_2), "action_group_action_2", reader)
    assert @controller.authorized?
    request!(MockUser.new(:test_action_group_2), "action_group_action_1", reader)
    assert !@controller.authorized?
    request!(nil, "action_group_action_2", reader)
    assert !@controller.authorized?
  end
  
  def test_filter_access
    assert !@controller.class.before_filters.empty?
    
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test
          has_permission_on :specific_mocks, :to => :show
        end
      end
    }
    
    request!(MockUser.new(:test_role), "test_action", reader)
    assert @controller.authorized?
    
    request!(MockUser.new(:test_role), "test_action_2", reader)
    assert !@controller.authorized?
    
    request!(MockUser.new(:test_role_2), "test_action", reader)
    assert_response :forbidden
    assert !@controller.authorized?
    
    request!(MockUser.new(:test_role), "show", reader)
    assert @controller.authorized?
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
    request!(MockUser.new(:test_role), "create", reader)
    assert @controller.authorized?
  end
  
  def test_filter_access_unprotected_actions
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
        end
      end
    }
    request!(MockUser.new(:test_role), "unprotected_action", reader)
    assert @controller.authorized?
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
          has_permission_on :specific_mocks, :to => :read
        end
      end
    }
    request!(MockUser.new(:test_role), "show", reader)
    assert @controller.authorized?
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
    request!(MockUser.new(:test_role), "new", reader)
    assert @controller.authorized?
  end
  
  def test_existing_instance_var_remains_unchanged
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :id => is { 5 }
          end
        end
      end
    }
    mock_object = MockDataObject.new(:id => 5)
    @controller.send(:instance_variable_set, :"@load_mock_object",
        mock_object)
    request!(MockUser.new(:test_role), "edit_2", reader)
    assert_equal mock_object, 
      @controller.send(:instance_variable_get, :"@load_mock_object")
    assert @controller.authorized?
  end

  def test_permitted_to_without_context
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :specific_mocks, :to => :test
        end
      end
    }
    @controller.current_user = MockUser.new(:test_role)
    @controller.authorization_engine = Authorization::Engine.new(reader)
    assert @controller.permitted_to?(:test)
  end
end


##################
class AllMocksController < MocksController
  filter_access_to :all
  filter_access_to :view, :require => :test, :context => :permissions
  define_action_methods :show, :view
end
class AllActionsControllerTest < ActionController::TestCase
  tests AllMocksController
  def test_filter_access_all
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test
          has_permission_on :all_mocks, :to => :show
        end
      end
    }
    
    request!(MockUser.new(:test_role), "show", reader)
    assert @controller.authorized?
    
    request!(MockUser.new(:test_role), "view", reader)
    assert @controller.authorized?
    
    request!(MockUser.new(:test_role_2), "show", reader)
    assert !@controller.authorized?
  end
end


##################
class LoadMockObjectsController < MocksController
  filter_access_to :show, :attribute_check => true, :model => LoadMockObject
  filter_access_to :edit, :attribute_check => true
  filter_access_to :update, :delete, :attribute_check => true,
                   :load_method => lambda {MockDataObject.new(:test => 1)}
  filter_access_to :create do
    permitted_to! :edit, :load_mock_objects
  end
  filter_access_to :view, :attribute_check => true, :load_method => :load_method
  def load_method
    MockDataObject.new(:test => 2)
  end
  define_action_methods :show, :edit, :update, :delete, :create, :view
end
class LoadObjectControllerTest < ActionController::TestCase
  tests LoadMockObjectsController
  
  def test_filter_access_with_object_load
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :load_mock_objects, :to => [:show, :edit] do
            if_attribute :id => is {"1"}
          end
        end
      end
    }
    
    request!(MockUser.new(:test_role), "show", reader, :id => 2)
    assert !@controller.authorized?
    
    request!(MockUser.new(:test_role), "show", reader, :id => 1,
      :clear => [:@load_mock_object])
    assert @controller.authorized?
    
    request!(MockUser.new(:test_role), "edit", reader, :id => 1,
      :clear => [:@load_mock_object])
    assert @controller.authorized?
    assert @controller.instance_variable_defined?(:@load_mock_object)
  end

  def test_filter_access_object_load_without_param
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :load_mock_objects, :to => [:show, :edit] do
            if_attribute :id => is {"1"}
          end
        end
      end
    }

    assert_raise RuntimeError, "No id param supplied" do
      request!(MockUser.new(:test_role), "show", reader)
    end
    
    Authorization::AuthorizationInController.failed_auto_loading_is_not_found = false
    assert_nothing_raised "Load error is only logged" do
      request!(MockUser.new(:test_role), "show", reader)
    end
    assert !@controller.authorized?
    Authorization::AuthorizationInController.failed_auto_loading_is_not_found = true
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
    
    request!(MockUser.new(:test_role), "delete", reader)
    assert !@controller.authorized?
    
    request!(MockUser.new(:test_role), "view", reader)
    assert @controller.authorized?
    
    request!(MockUser.new(:test_role), "update", reader)
    assert @controller.authorized?
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
    
    request!(MockUser.new(:test_role), "create", reader)
    assert @controller.authorized?
    
    request!(MockUser.new(:test_role_2), "create", reader)
    assert !@controller.authorized?
  end
end


##################
class AccessOverwritesController < MocksController
  filter_access_to :test_action, :test_action_2, 
    :require => :test, :context => :permissions_2
  filter_access_to :test_action, :require => :test, :context => :permissions
  define_action_methods :test_action, :test_action_2
end
class AccessOverwritesControllerTest < ActionController::TestCase
  def test_filter_access_overwrite
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test
        end
      end
    }
    request!(MockUser.new(:test_role), "test_action_2", reader)
    assert !@controller.authorized?
    
    request!(MockUser.new(:test_role), "test_action", reader)
    assert @controller.authorized?
  end
end


##################
class PeopleController < MocksController
  filter_access_to :all
  define_action_methods :show
end
class PluralizationControllerTest < ActionController::TestCase
  tests PeopleController
  
  def test_filter_access_people_controller
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :people, :to => :show
        end
      end
    }
    request!(MockUser.new(:test_role), "show", reader)
    assert @controller.authorized?
  end
end


##################
class CommonController < MocksController
  filter_access_to :delete, :context => :common
  filter_access_to :all
end
class CommonChild1Controller < CommonController
  filter_access_to :all, :context => :context_1
end
class CommonChild2Controller < CommonController
  filter_access_to :delete
  define_action_methods :show
end
class HierachicalControllerTest < ActionController::TestCase
  tests CommonChild2Controller
  def test_controller_hierarchy
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :mocks, :to => [:delete, :show]
        end
      end
    }
    request!(MockUser.new(:test_role), "show", reader)
    assert !@controller.authorized?
    request!(MockUser.new(:test_role), "delete", reader)
    assert !@controller.authorized?
  end
end

##################
module Name
  class SpacedThingsController < MocksController
    filter_access_to :show
    filter_access_to :update, :context => :spaced_things
    define_action_methods :show, :update
  end
end
class NameSpacedControllerTest < ActionController::TestCase
  tests Name::SpacedThingsController
  def test_context
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :permitted_role do
          has_permission_on :name_spaced_things, :to => :show
          has_permission_on :spaced_things, :to => :update
        end
        role :prohibited_role do
          has_permission_on :name_spaced_things, :to => :update
          has_permission_on :spaced_things, :to => :show
        end
      end
    }
    request!(MockUser.new(:permitted_role), "show", reader)
    assert @controller.authorized?
    request!(MockUser.new(:prohibited_role), "show", reader)
    assert !@controller.authorized?
    request!(MockUser.new(:permitted_role), "update", reader)
    assert @controller.authorized?
    request!(MockUser.new(:prohibited_role), "update", reader)
    assert !@controller.authorized?
  end
end

module Deep
  module NameSpaced
    class ThingsController < MocksController
      filter_access_to :show
      filter_access_to :update, :context => :things
      define_action_methods :show, :update
    end
  end
end
class DeepNameSpacedControllerTest < ActionController::TestCase
  tests Deep::NameSpaced::ThingsController
  def test_context
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :permitted_role do
          has_permission_on :deep_name_spaced_things, :to => :show
          has_permission_on :things, :to => :update
        end
        role :prohibited_role do
          has_permission_on :deep_name_spaced_things, :to => :update
          has_permission_on :things, :to => :show
        end
      end
    }
    request!(MockUser.new(:permitted_role), "show", reader)
    assert @controller.authorized?
    request!(MockUser.new(:prohibited_role), "show", reader)
    assert !@controller.authorized?
    request!(MockUser.new(:permitted_role), "update", reader)
    assert @controller.authorized?
    request!(MockUser.new(:prohibited_role), "update", reader)
    assert !@controller.authorized?
  end
end