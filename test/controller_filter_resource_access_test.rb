require File.join(File.dirname(__FILE__), 'test_helper.rb')

class BasicResource < MockDataObject
  def self.name
    "BasicResource"
  end
end
class BasicResourcesController < MocksController
  filter_resource_access
  define_resource_actions
end
class BasicResourcesControllerTest < ActionController::TestCase
  def test_basic_filter_index
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :allowed_role do
          has_permission_on :basic_resources, :to => :index do
            if_attribute :id => is {"1"}
          end
        end
      end
    }

    allowed_user = MockUser.new(:allowed_role)
    request!(MockUser.new(:another_role), :index, reader)
    assert !@controller.authorized?
    request!(allowed_user, :index, reader)
    assert @controller.authorized?
  end

  def test_basic_filter_show_with_id
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :allowed_role do
          has_permission_on :basic_resources, :to => :show do
            if_attribute :id => is {"1"}
          end
        end
      end
    }

    allowed_user = MockUser.new(:allowed_role)
    request!(allowed_user, :show, reader, :id => "2")
    assert !@controller.authorized?
    request!(allowed_user, :show, reader, :id => "1", :clear => [:@basic_resource])
    assert @controller.authorized?
  end

  def test_basic_filter_new_with_params
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :allowed_role do
          has_permission_on :basic_resources, :to => :new do
            if_attribute :id => is {"1"}
          end
        end
      end
    }

    allowed_user = MockUser.new(:allowed_role)
    request!(allowed_user, :new, reader, :basic_resource => {:id => "2"})
    assert !@controller.authorized?
    request!(allowed_user, :new, reader, :basic_resource => {:id => "1"},
        :clear => [:@basic_resource])
    assert @controller.authorized?
  end
end


class NestedResource < MockDataObject
  def initialize (attributes = {})
    if attributes[:id]
      attributes[:parent_mock] ||= ParentMock.new(:id => attributes[:id])
    end
    super(attributes)
  end
  def self.name
    "NestedResource"
  end
end

class ShallowNestedResource < MockDataObject
  def initialize (attributes = {})
    if attributes[:id]
      attributes[:parent_mock] ||= ParentMock.new(:id => attributes[:id])
    end
    super(attributes)
  end
  def self.name
    "ShallowNestedResource"
  end
end

class ParentMock < MockDataObject
  def nested_resources
    Class.new do
      def initialize (parent_mock)
        @parent_mock = parent_mock
      end
      def new (attributes = {})
        NestedResource.new(attributes.merge(:parent_mock => @parent_mock))
      end
    end.new(self)
  end

  alias :shallow_nested_resources :nested_resources

  def == (other)
    id == other.id
  end
  def self.name
    "ParentMock"
  end
end

class NestedResourcesController < MocksController
  filter_resource_access :nested_in => :parent_mocks
  define_resource_actions
end
class NestedResourcesControllerTest < ActionController::TestCase
  def test_nested_filter_index
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :allowed_role do
          has_permission_on :nested_resources, :to => :index do
            if_attribute :parent_mock => is {ParentMock.find("1")}
          end
        end
      end
    }

    allowed_user = MockUser.new(:allowed_role)
    request!(MockUser.new(:another_role), :index, reader, :parent_mock_id => "2")
    assert !@controller.authorized?
    request!(allowed_user, :index, reader, :parent_mock_id => "2",
        :clear => [:@nested_resource, :@parent_mock])
    assert !@controller.authorized?
    request!(allowed_user, :index, reader, :parent_mock_id => "1",
        :clear => [:@nested_resource, :@parent_mock])
    assert @controller.authorized?
  end

  def test_nested_filter_show_with_id
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :allowed_role do
          has_permission_on :nested_resources, :to => :show do
            if_attribute :parent_mock => is {ParentMock.find("1")}
          end
        end
      end
    }

    allowed_user = MockUser.new(:allowed_role)
    request!(allowed_user, :show, reader, :id => "2", :parent_mock_id => "2")
    assert !@controller.authorized?
    request!(allowed_user, :show, reader, :id => "1", :parent_mock_id => "1",
        :clear => [:@nested_resource, :@parent_mock])
    assert @controller.authorized?
  end

  def test_nested_filter_new_with_params
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :allowed_role do
          has_permission_on :nested_resources, :to => :new do
            if_attribute :parent_mock => is {ParentMock.find("1")}
          end
        end
      end
    }

    allowed_user = MockUser.new(:allowed_role)
    request!(allowed_user, :new, reader, :parent_mock_id => "2",
        :nested_resource => {:id => "2"})
    assert !@controller.authorized?
    request!(allowed_user, :new, reader, :parent_mock_id => "1",
        :nested_resource => {:id => "1"},
        :clear => [:@nested_resource, :@parent_mock])
    assert @controller.authorized?
  end
end

class ShallowNestedResourcesController < MocksController
  filter_resource_access :nested_in => :parent_mocks,
                         :shallow => true,
                         :additional_member => :additional_member_action
  define_resource_actions
  define_action_methods :additional_member_action
end
class ShallowNestedResourcesControllerTest < ActionController::TestCase
  def test_nested_filter_index
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :allowed_role do
          has_permission_on :shallow_nested_resources, :to => :index do
            if_attribute :parent_mock => is {ParentMock.find("1")}
          end
        end
      end
    }

    allowed_user = MockUser.new(:allowed_role)
    request!(MockUser.new(:another_role), :index, reader, :parent_mock_id => "2")
    assert !@controller.authorized?
    request!(allowed_user, :index, reader, :parent_mock_id => "2",
        :clear => [:@shallow_nested_resource, :@parent_mock])
    assert !@controller.authorized?
    request!(allowed_user, :index, reader, :parent_mock_id => "1",
        :clear => [:@shallow_nested_resource, :@parent_mock])
    assert assigns(:parent_mock)
    assert @controller.authorized?
  end

  def test_nested_filter_show_with_id
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :allowed_role do
          has_permission_on :shallow_nested_resources, :to => :show do
            if_attribute :parent_mock => is {ParentMock.find("1")}
          end
        end
      end
    }

    allowed_user = MockUser.new(:allowed_role)
    request!(allowed_user, :show, reader, :id => "2", :parent_mock_id => "2")
    assert !@controller.authorized?
    request!(allowed_user, :show, reader, :id => "1",
        :clear => [:@shallow_nested_resource, :@parent_mock])
    assert !assigns(:parent_mock)
    assert assigns(:shallow_nested_resource)
    assert @controller.authorized?
  end

  def test_nested_filter_new_with_params
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :allowed_role do
          has_permission_on :shallow_nested_resources, :to => :new do
            if_attribute :parent_mock => is {ParentMock.find("1")}
          end
        end
      end
    }

    allowed_user = MockUser.new(:allowed_role)
    request!(allowed_user, :new, reader, :parent_mock_id => "2",
        :shallow_nested_resource => {:id => "2"})
    assert !@controller.authorized?
    request!(allowed_user, :new, reader, :parent_mock_id => "1",
        :shallow_nested_resource => {:id => "1"},
        :clear => [:@shallow_nested_resource, :@parent_mock])
    assert assigns(:parent_mock)
    assert assigns(:shallow_nested_resource)
    assert @controller.authorized?
  end

  def test_nested_filter_additional_member_action_with_id
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :allowed_role do
          has_permission_on :shallow_nested_resources, :to => :additional_member_action do
            if_attribute :parent_mock => is {ParentMock.find("1")}
          end
        end
      end
    }

    allowed_user = MockUser.new(:allowed_role)
    request!(allowed_user, :additional_member_action, reader, :id => "2", :parent_mock_id => "2")
    assert !@controller.authorized?
    request!(allowed_user, :additional_member_action, reader, :id => "1",
        :clear => [:@shallow_nested_resource, :@parent_mock])
    assert !assigns(:parent_mock)
    assert assigns(:shallow_nested_resource)
    assert @controller.authorized?
  end
end


class CustomMembersCollectionsResourceController < MocksController
  def self.controller_name
    "basic_resources"
  end
  filter_resource_access :member => [[:other_show, :read]],
      :collection => {:search => :read}, :new => [:other_new]
  define_action_methods :other_new, :search, :other_show
end
class CustomMembersCollectionsResourceControllerTest < ActionController::TestCase
  def test_custom_members_filter_search
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :allowed_role do
          has_permission_on :basic_resources, :to => :read do
            if_attribute :id => is {"1"}
          end
        end
      end
    }

    request!(MockUser.new(:another_role), :search, reader)
    assert !@controller.authorized?
    request!(MockUser.new(:allowed_role), :search, reader)
    assert @controller.authorized?
  end

  def test_custom_members_filter_other_show
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :allowed_role do
          has_permission_on :basic_resources, :to => :read do
            if_attribute :id => is {"1"}
          end
        end
      end
    }

    allowed_user = MockUser.new(:allowed_role)
    request!(allowed_user, :other_show, reader, :id => "2")
    assert !@controller.authorized?
    request!(allowed_user, :other_show, reader, :id => "1", :clear => [:@basic_resource])
    assert @controller.authorized?
  end

  def test_custom_members_filter_other_new
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :allowed_role do
          has_permission_on :basic_resources, :to => :other_new do
            if_attribute :id => is {"1"}
          end
        end
      end
    }

    allowed_user = MockUser.new(:allowed_role)
    request!(allowed_user, :other_new, reader, :basic_resource => {:id => "2"})
    assert !@controller.authorized?
    request!(allowed_user, :other_new, reader, :basic_resource => {:id => "1"},
        :clear => [:@basic_resource])
    assert @controller.authorized?
  end
end


class AdditionalMembersCollectionsResourceController < MocksController
  def self.controller_name
    "basic_resources"
  end
  filter_resource_access :additional_member => :other_show,
      :additional_collection => [:search], :additional_new => {:other_new => :new}
  define_resource_actions
  define_action_methods :other_new, :search, :other_show
end
class AdditionalMembersCollectionsResourceControllerTest < ActionController::TestCase
  def test_additional_members_filter_search_index
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :allowed_role do
          has_permission_on :basic_resources, :to => [:search, :index] do
            if_attribute :id => is {"1"}
          end
        end
      end
    }

    request!(MockUser.new(:another_role), :search, reader)
    assert !@controller.authorized?
    request!(MockUser.new(:another_role), :index, reader)
    assert !@controller.authorized?
    request!(MockUser.new(:allowed_role), :search, reader)
    assert @controller.authorized?
    request!(MockUser.new(:allowed_role), :index, reader)
    assert @controller.authorized?
  end

  def test_additional_members_filter_other_show
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :allowed_role do
          has_permission_on :basic_resources, :to => [:show, :other_show] do
            if_attribute :id => is {"1"}
          end
        end
      end
    }

    allowed_user = MockUser.new(:allowed_role)
    request!(allowed_user, :other_show, reader, :id => "2")
    assert !@controller.authorized?
    request!(allowed_user, :show, reader, :id => "2", :clear => [:@basic_resource])
    assert !@controller.authorized?
    request!(allowed_user, :other_show, reader, :id => "1", :clear => [:@basic_resource])
    assert @controller.authorized?
    request!(allowed_user, :show, reader, :id => "1", :clear => [:@basic_resource])
    assert @controller.authorized?
  end

  def test_additional_members_filter_other_new
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :allowed_role do
          has_permission_on :basic_resources, :to => :new do
            if_attribute :id => is {"1"}
          end
        end
      end
    }

    allowed_user = MockUser.new(:allowed_role)
    request!(allowed_user, :other_new, reader, :basic_resource => {:id => "2"})
    assert !@controller.authorized?
    request!(allowed_user, :new, reader, :basic_resource => {:id => "2"},
        :clear => [:@basic_resource])
    assert !@controller.authorized?

    request!(allowed_user, :other_new, reader, :basic_resource => {:id => "1"},
        :clear => [:@basic_resource])
    assert @controller.authorized?
    request!(allowed_user, :new, reader, :basic_resource => {:id => "1"},
        :clear => [:@basic_resource])
    assert @controller.authorized?
  end
end


class CustomMethodsResourceController < MocksController
  # not implemented yet
end


class ExplicitContextResourceController < MocksController
  filter_resource_access :context => :basic_resources
  define_resource_actions
end
class ExplicitContextResourceControllerTest < ActionController::TestCase
  def test_explicit_context_filter_index
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :allowed_role do
          has_permission_on :basic_resources, :to => :index do
            if_attribute :id => is {"1"}
          end
        end
      end
    }

    allowed_user = MockUser.new(:allowed_role)
    request!(MockUser.new(:another_role), :index, reader)
    assert !@controller.authorized?
    request!(allowed_user, :index, reader)
    assert @controller.authorized?
  end

  def test_explicit_context_filter_show_with_id
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :allowed_role do
          has_permission_on :basic_resources, :to => :show do
            if_attribute :id => is {"1"}
          end
        end
      end
    }

    allowed_user = MockUser.new(:allowed_role)
    request!(allowed_user, :show, reader, :id => "2")
    assert !@controller.authorized?
    request!(allowed_user, :show, reader, :id => "1", :clear => [:@basic_resource])
    assert @controller.authorized?
  end

  def test_explicit_context_filter_new_with_params
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :allowed_role do
          has_permission_on :basic_resources, :to => :new do
            if_attribute :id => is {"1"}
          end
        end
      end
    }

    allowed_user = MockUser.new(:allowed_role)
    request!(allowed_user, :new, reader, :basic_resource => {:id => "2"})
    assert !@controller.authorized?
    request!(allowed_user, :new, reader, :basic_resource => {:id => "1"},
        :clear => [:@basic_resource])
    assert @controller.authorized?
  end
end
