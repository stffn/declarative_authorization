require File.join(File.dirname(__FILE__), 'test_helper.rb')
require File.join(File.dirname(__FILE__), %w{.. lib declarative_authorization helper})


class HelperMocksController < MocksController
  filter_access_to :action, :require => :show, :context => :mocks
  define_action_methods :action
end
class HelperTest < ActionController::TestCase
  tests HelperMocksController
  include Authorization::AuthorizationHelper
  attr_reader :controller
  
  def test_permit
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :mocks, :to => :show
        end
        role :test_role_2 do
          has_permission_on :mocks, :to => :update
        end
      end
    }
    user = MockUser.new(:test_role)
    request!(user, :action, reader)
    
    assert permitted_to?(:show, :mocks)
    assert !permitted_to?(:update, :mocks)
    
    block_evaled = false
    permitted_to?(:show, :mocks) do
      block_evaled = true
    end
    assert block_evaled
    
    block_evaled = false
    permitted_to?(:update, :mocks) do
      block_evaled = true
    end
    assert !block_evaled
  end

  def test_permit_with_object
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :mocks do
            to :show
            if_attribute :test_attr => is {user.test_attr}
          end
        end
      end
    }
    user = MockUser.new(:test_role, :test_attr => 1)
    mock = MockDataObject.new(:test_attr => 1)
    mock_2 = MockDataObject.new(:test_attr => 2)
    request!(user, :action, reader)
    
    assert permitted_to?(:show, mock)
    assert permitted_to?(:show, :mocks)
    assert !permitted_to?(:show, mock_2)
  end

  def test_permit_with_object_and_context
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :other_mocks do
            to :show
            if_attribute :test_attr => is {user.test_attr}
          end
        end
      end
    }
    user = MockUser.new(:test_role, :test_attr => 1)
    mock = MockDataObject.new(:test_attr => 1)
    mock_2 = MockDataObject.new(:test_attr => 2)
    request!(user, :action, reader)

    assert permitted_to?(:show, mock, :context => :other_mocks)
    assert !permitted_to?(:show, mock_2, :context => :other_mocks)
  end
  
  def test_has_role
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :mocks, :to => :show
        end
      end
    }
    user = MockUser.new(:test_role)
    request!(user, :action, reader)
    
    assert has_role?(:test_role)
    assert !has_role?(:test_role2)
    
    block_evaled = false
    has_role?(:test_role) do
      block_evaled = true
    end
    assert block_evaled
    
    block_evaled = false
    has_role?(:test_role2) do
      block_evaled = true
    end
    assert !block_evaled
  end

  def test_has_role_with_guest_user
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
      end
    }
    request!(nil, :action, reader)

    assert !has_role?(:test_role)

    block_evaled = false
    has_role?(:test_role) do
      block_evaled = true
    end
    assert !block_evaled
  end
  
  def test_has_role_with_hierarchy
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :mocks, :to => :show
        end
        role :other_role do
          has_permission_on :another_mocks, :to => :show
        end

        role :root do
          includes :test_role
        end
      end
    }    
    
    user = MockUser.new(:root)
    request!(user, :action, reader)
    
    assert has_role_with_hierarchy?(:test_role)
    assert !has_role_with_hierarchy?(:other_role)

    block_evaled = false
    has_role_with_hierarchy?(:test_role) do
      block_evaled = true
    end
    assert block_evaled
    
    block_evaled = false
    has_role_with_hierarchy?(:test_role2) do
      block_evaled = true
    end
    assert !block_evaled

  end
  
  
end