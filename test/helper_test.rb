require File.join(File.dirname(__FILE__), 'test_helper.rb')
require File.dirname(__FILE__) + '/../lib/in_controller.rb'
require File.dirname(__FILE__) + '/../lib/helper.rb'


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
  
end