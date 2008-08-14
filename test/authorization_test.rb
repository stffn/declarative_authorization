require File.join(File.dirname(__FILE__), 'test_helper.rb')

class AuthorizationTest < Test::Unit::TestCase
  
  def test_permit
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    assert engine.permit?(:test, :context => :permissions, 
      :user => MockUser.new(:test_role, :test_role_2))
    assert !engine.permit?(:test_2, :context => :permissions_2, 
      :user => MockUser.new(:test_role))
    assert !engine.permit?(:test, :context => :permissions, 
      :user => MockUser.new(:test_role_2))
  end
  
  def test_role_hierarchy
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          includes :lower_role
          has_permission_on :permissions, :to => :test
        end
        role :lower_role do
          has_permission_on :permissions, :to => :lower
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    assert engine.permit?(:lower, :context => :permissions, 
      :user => MockUser.new(:test_role))
  end
    
  def test_role_hierarchy_infinity
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          includes :lower_role
          has_permission_on :permissions, :to => :test
        end
        role :lower_role do
          includes :higher_role
          has_permission_on :permissions, :to => :lower
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    assert engine.permit?(:lower, :context => :permissions, 
      :user => MockUser.new(:test_role))
  end
  
  def test_privilege_hierarchy
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      privileges do
        privilege :test, :permissions do
          includes :lower
        end
      end
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    assert engine.permit?(:lower, :context => :permissions, 
      :user => MockUser.new(:test_role))
  end
  
  def test_privilege_hierarchy_without_context
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      privileges do
        privilege :read do
          includes :list, :show
        end
      end
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :read
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    assert engine.permit?(:list, :context => :permissions, 
      :user => MockUser.new(:test_role))
  end
  
  def test_attribute_is
    reader = Authorization::Reader::DSLReader.new
    reader.parse %|
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :test_attr => is { user.test_attr }
          end
        end
      end
    |
    engine = Authorization::Engine.new(reader)
    assert engine.permit?(:test, :context => :permissions, 
              :user => MockUser.new(:test_role, :test_attr => 1),
              :object => MockDataObject.new(:test_attr => 1))
    assert((not(engine.permit?(:test, :context => :permissions, 
              :user => MockUser.new(:test_role, :test_attr => 2),
              :object => MockDataObject.new(:test_attr => 1)))))
  end
  
  def test_attribute_contains
    reader = Authorization::Reader::DSLReader.new
    reader.parse %|
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :test_attr => contains { user.test_attr }
          end
        end
      end
    |
    engine = Authorization::Engine.new(reader)
    assert engine.permit?(:test, :context => :permissions, 
              :user => MockUser.new(:test_role, :test_attr => 1),
              :object => MockDataObject.new(:test_attr => [1,2]))
    assert !engine.permit?(:test, :context => :permissions, 
              :user => MockUser.new(:test_role, :test_attr => 3),
              :object => MockDataObject.new(:test_attr => [1,2]))
  end
  
  def test_attribute_deep
    reader = Authorization::Reader::DSLReader.new
    reader.parse %|
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :test_attr_1 => {:test_attr_2 => contains { 1 }}
          end
        end
      end
    |
    engine = Authorization::Engine.new(reader)
    attr_1_struct = Struct.new(:test_attr_2)
    assert engine.permit?(:test, :context => :permissions,
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:test_attr_1 => attr_1_struct.new([1,2])))
    assert !engine.permit?(:test, :context => :permissions,
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:test_attr_1 => attr_1_struct.new([3,4])))
    assert_equal [{:test_attr_1 => {:test_attr_2 => [:contains, 1]}}], 
      engine.obligations(:test, :context => :permissions, 
          :user => MockUser.new(:test_role))
  end
  
  def test_attribute_non_block
    reader = Authorization::Reader::DSLReader.new
    reader.parse %|
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :test_attr => 1
          end
        end
      end
    |
    engine = Authorization::Engine.new(reader)
    assert engine.permit?(:test, :context => :permissions,
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:test_attr => 1))
    assert !engine.permit?(:test, :context => :permissions, 
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:test_attr => 2))
  end
  
  def test_attribute_multiple
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :test_attr => 1
            if_attribute :test_attr => 2  # or
          end
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    assert engine.permit?(:test, :context => :permissions,
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:test_attr => 1))
    assert engine.permit?(:test, :context => :permissions, 
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:test_attr => 2))
  end
end
