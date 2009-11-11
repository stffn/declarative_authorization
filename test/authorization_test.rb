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
  
  def test_permit_context_people
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :people, :to => :test
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    assert engine.permit?(:test, :context => :people, 
      :user => MockUser.new(:test_role))
  end

  def test_permit_multiple_contexts
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on [:permissions, :permissions_2], :to => :test
          has_permission_on :permissions_4, :permissions_5, :to => :test
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    assert engine.permit?(:test, :context => :permissions, 
      :user => MockUser.new(:test_role))
    assert engine.permit?(:test, :context => :permissions_2, 
      :user => MockUser.new(:test_role))
    assert !engine.permit?(:test, :context => :permissions_3, 
      :user => MockUser.new(:test_role))
      
    assert  engine.permit?(:test, :context => :permissions_4, :user => MockUser.new(:test_role))
    assert  engine.permit?(:test, :context => :permissions_5, :user => MockUser.new(:test_role))
  end
  
  def test_obligations_without_conditions
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    assert_equal [{}], engine.obligations(:test, :context => :permissions, 
      :user => MockUser.new(:test_role))
  end
  
  def test_obligations_with_conditions
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :attr => is { user.attr }
          end
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    assert_equal [{:attr => [:is, 1]}], 
      engine.obligations(:test, :context => :permissions, 
          :user => MockUser.new(:test_role, :attr => 1))
  end

  def test_obligations_with_anded_conditions
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test, :join_by => :and do
            if_attribute :attr => is { user.attr }
            if_attribute :attr_2 => is { user.attr_2 }
          end
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    assert_equal [{:attr => [:is, 1], :attr_2 => [:is, 2]}],
      engine.obligations(:test, :context => :permissions,
          :user => MockUser.new(:test_role, :attr => 1, :attr_2 => 2))
  end

  def test_obligations_with_deep_anded_conditions
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test, :join_by => :and do
            if_attribute :attr => { :deeper_attr => is { user.deeper_attr }}
            if_attribute :attr => { :deeper_attr_2 => is { user.deeper_attr_2 }}
          end
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    assert_equal [{:attr => { :deeper_attr => [:is, 1], :deeper_attr_2 => [:is, 2] } }],
      engine.obligations(:test, :context => :permissions,
          :user => MockUser.new(:test_role, :deeper_attr => 1, :deeper_attr_2 => 2))
  end

  def test_obligations_with_has_many
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :attrs => { :deeper_attr => is { user.deeper_attr } }
          end
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    assert_equal [{:attrs => {:deeper_attr => [:is, 1]}}],
      engine.obligations(:test, :context => :permissions,
          :user => MockUser.new(:test_role, :deeper_attr => 1))
  end
  
  def test_obligations_with_conditions_and_empty
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test
          has_permission_on :permissions, :to => :test do
            if_attribute :attr => is { user.attr }
          end
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    assert_equal [{}, {:attr => [:is, 1]}], 
      engine.obligations(:test, :context => :permissions, 
          :user => MockUser.new(:test_role, :attr => 1))
  end

  def test_obligations_with_permissions
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :attr => is { user.attr }
          end
          has_permission_on :permission_children, :to => :test do
            if_permitted_to :test, :permission, :context => :permissions
          end
          has_permission_on :permission_children_2, :to => :test do
            if_permitted_to :test, :permission
          end
          has_permission_on :permission_children_children, :to => :test do
            if_permitted_to :test, :permission_child => :permission,
                            :context => :permissions
          end
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    assert_equal [{:permission => {:attr => [:is, 1]}}],
      engine.obligations(:test, :context => :permission_children,
          :user => MockUser.new(:test_role, :attr => 1))
    assert_equal [{:permission => {:attr => [:is, 1]}}],
      engine.obligations(:test, :context => :permission_children_2,
          :user => MockUser.new(:test_role, :attr => 1))
    assert_equal [{:permission_child => {:permission => {:attr => [:is, 1]}}}],
      engine.obligations(:test, :context => :permission_children_children,
          :user => MockUser.new(:test_role, :attr => 1))
  end

  def test_obligations_with_has_many_permissions
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :attr => is { user.attr }
          end
          has_permission_on :permission_children, :to => :test do
            if_permitted_to :test, :permissions, :context => :permissions
          end
          has_permission_on :permission_children_2, :to => :test do
            if_permitted_to :test, :permissions
          end
          has_permission_on :permission_children_children, :to => :test do
            if_permitted_to :test, :permission_child => :permissions,
                            :context => :permissions
          end
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    assert_equal [{:permissions => {:attr => [:is, 1]}}],
      engine.obligations(:test, :context => :permission_children,
          :user => MockUser.new(:test_role, :attr => 1))
    assert_equal [{:permissions => {:attr => [:is, 1]}}],
      engine.obligations(:test, :context => :permission_children_2,
          :user => MockUser.new(:test_role, :attr => 1))
    assert_equal [{:permission_child => {:permissions => {:attr => [:is, 1]}}}],
      engine.obligations(:test, :context => :permission_children_children,
          :user => MockUser.new(:test_role, :attr => 1))
  end

  def test_obligations_with_permissions_multiple
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :attr => is { 1 }
            if_attribute :attr => is { 2 }
          end
          has_permission_on :permission_children_children, :to => :test do
            if_permitted_to :test, :permission_child => :permission
          end
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    assert_equal [{:permission_child => {:permission => {:attr => [:is, 1]}}},
        {:permission_child => {:permission => {:attr => [:is, 2]}}}],
      engine.obligations(:test, :context => :permission_children_children,
          :user => MockUser.new(:test_role))
  end

  def test_obligations_with_permissions_and_anded_conditions
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permission_children, :to => :test, :join_by => :and do
            if_permitted_to :test, :permission
            if_attribute :test_attr => 1
          end
          has_permission_on :permissions, :to => :test do
            if_attribute :test_attr => 1
          end
        end
      end
    }
    engine = Authorization::Engine.new(reader)

    assert_equal [{:test_attr => [:is, 1], :permission => {:test_attr => [:is, 1]}}],
      engine.obligations(:test, :context => :permission_children,
          :user => MockUser.new(:test_role))
  end
  
  def test_guest_user
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :guest do
          has_permission_on :permissions, :to => :test
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    assert engine.permit?(:test, :context => :permissions)
    assert !engine.permit?(:test, :context => :permissions_2)
  end
  
  def test_invalid_user_model
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :guest do
          has_permission_on :permissions, :to => :test
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    assert_raise(Authorization::AuthorizationUsageError) do
      engine.permit?(:test, :context => :permissions, :user => MockUser.new(1, 2))
    end
    assert_raise(Authorization::AuthorizationUsageError) do
      engine.permit?(:test, :context => :permissions, :user => MockDataObject.new)
    end
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
            if_attribute :test_attr => 3
          end
        end
      end
    |
    engine = Authorization::Engine.new(reader)
    assert engine.permit?(:test, :context => :permissions, 
              :user => MockUser.new(:test_role, :test_attr => 1),
              :object => MockDataObject.new(:test_attr => 1))
    assert engine.permit?(:test, :context => :permissions, 
              :user => MockUser.new(:test_role, :test_attr => 2),
              :object => MockDataObject.new(:test_attr => 3))
    assert((not(engine.permit?(:test, :context => :permissions, 
              :user => MockUser.new(:test_role, :test_attr => 2),
              :object => MockDataObject.new(:test_attr => 1)))))
  end

  def test_attribute_is_not
    reader = Authorization::Reader::DSLReader.new
    reader.parse %|
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :test_attr => is_not { user.test_attr }
          end
        end
      end
    |
    engine = Authorization::Engine.new(reader)
    assert !engine.permit?(:test, :context => :permissions,
              :user => MockUser.new(:test_role, :test_attr => 1),
              :object => MockDataObject.new(:test_attr => 1))
    assert engine.permit?(:test, :context => :permissions,
              :user => MockUser.new(:test_role, :test_attr => 2),
              :object => MockDataObject.new(:test_attr => 1))
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

  def test_attribute_does_not_contain
    reader = Authorization::Reader::DSLReader.new
    reader.parse %|
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :test_attr => does_not_contain { user.test_attr }
          end
        end
      end
    |
    engine = Authorization::Engine.new(reader)
    assert !engine.permit?(:test, :context => :permissions,
              :user => MockUser.new(:test_role, :test_attr => 1),
              :object => MockDataObject.new(:test_attr => [1,2]))
    assert engine.permit?(:test, :context => :permissions,
              :user => MockUser.new(:test_role, :test_attr => 3),
              :object => MockDataObject.new(:test_attr => [1,2]))
  end
  
  def test_attribute_in_array
    reader = Authorization::Reader::DSLReader.new
    reader.parse %|
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :test_attr => is_in { [1,2] }
            if_attribute :test_attr => [2,3]
          end
        end
      end
    |
    engine = Authorization::Engine.new(reader)
    assert engine.permit?(:test, :context => :permissions, 
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:test_attr => 1))
    assert engine.permit?(:test, :context => :permissions, 
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:test_attr => 3))
    assert !engine.permit?(:test, :context => :permissions, 
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:test_attr => 4))
  end

  def test_attribute_not_in_array
    reader = Authorization::Reader::DSLReader.new
    reader.parse %|
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :test_attr => is_not_in { [1,2] }
          end
        end
      end
    |
    engine = Authorization::Engine.new(reader)
    assert !engine.permit?(:test, :context => :permissions,
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:test_attr => 1))
    assert engine.permit?(:test, :context => :permissions,
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:test_attr => 4))
  end

  def test_attribute_intersects_with
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :test_attrs => intersects_with { [1,2] }
          end
        end
        role :test_role_2 do
          has_permission_on :permissions, :to => :test do
            if_attribute :test_attrs => intersects_with { 1 }
          end
        end
      end
    }

    engine = Authorization::Engine.new(reader)
    assert_raise Authorization::AuthorizationUsageError do
      engine.permit?(:test, :context => :permissions,
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:test_attrs => 1 ))
    end
    assert_raise Authorization::AuthorizationUsageError do
      engine.permit?(:test, :context => :permissions,
              :user => MockUser.new(:test_role_2),
              :object => MockDataObject.new(:test_attrs => [1, 2] ))
    end
    assert engine.permit?(:test, :context => :permissions,
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:test_attrs => [1,3] ))
    assert !engine.permit?(:test, :context => :permissions,
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:test_attrs => [3,4] ))
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
    assert engine.permit?(:test, :context => :permissions,
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:test_attr_1 =>
                    MockDataObject.new(:test_attr_2 => [1,2])))
    assert !engine.permit?(:test, :context => :permissions,
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:test_attr_1 =>
                    MockDataObject.new(:test_attr_2 => [3,4])))
    assert_equal [{:test_attr_1 => {:test_attr_2 => [:contains, 1]}}], 
      engine.obligations(:test, :context => :permissions, 
          :user => MockUser.new(:test_role))
  end

  def test_attribute_has_many
    reader = Authorization::Reader::DSLReader.new
    reader.parse %|
      authorization do
        role :test_role do
          has_permission_on :companies, :to => :read do
            if_attribute :branches => {:city => is { user.city } }
          end
        end
      end
    |
    engine = Authorization::Engine.new(reader)

    company = MockDataObject.new(:branches => [
        MockDataObject.new(:city => 'Barcelona'),
        MockDataObject.new(:city => 'Paris')
      ])
    assert engine.permit!(:read, :context => :companies,
              :user => MockUser.new(:test_role, :city => 'Paris'),
              :object => company)
    assert !engine.permit?(:read, :context => :companies,
              :user => MockUser.new(:test_role, :city => 'London'),
              :object => company)
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

  class PermissionMock < MockDataObject
    def self.name
      "Permission"
    end
  end
  def test_attribute_with_permissions
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :test_attr => 1
          end
          has_permission_on :permission_children, :to => :test do
            if_permitted_to :test, :permission
          end
        end
      end
    }
    engine = Authorization::Engine.new(reader)

    perm_data_attr_1 = PermissionMock.new({:test_attr => 1})
    perm_data_attr_2 = PermissionMock.new({:test_attr => 2})
    assert engine.permit?(:test, :context => :permission_children,
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:permission => perm_data_attr_1))
    assert !engine.permit?(:test, :context => :permission_children,
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:permission => perm_data_attr_2))
  end

  def test_attribute_with_has_many_permissions
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :test_attr => 1
          end
          has_permission_on :permission_children, :to => :test do
            if_permitted_to :test, :permissions
          end
        end
      end
    }
    engine = Authorization::Engine.new(reader)

    perm_data_attr_1 = PermissionMock.new({:test_attr => 1})
    perm_data_attr_2 = PermissionMock.new({:test_attr => 2})
    assert engine.permit?(:test, :context => :permission_children,
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:permissions => [perm_data_attr_1]))
    assert !engine.permit?(:test, :context => :permission_children,
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:permissions => [perm_data_attr_2]))
  end

  def test_attribute_with_deep_permissions
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :test_attr => 1
          end
          has_permission_on :permission_children, :to => :test do
            if_permitted_to :test, :shallow_permission => :permission
          end
        end
      end
    }
    engine = Authorization::Engine.new(reader)

    perm_data_attr_1 = PermissionMock.new({:test_attr => 1})
    perm_data_attr_2 = PermissionMock.new({:test_attr => 2})
    assert engine.permit?(:test, :context => :permission_children,
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:shallow_permission =>
                MockDataObject.new(:permission => perm_data_attr_1)))
    assert !engine.permit?(:test, :context => :permission_children,
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:shallow_permission =>
                MockDataObject.new(:permission => perm_data_attr_2)))
  end

  def test_attribute_with_deep_has_many_permissions
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :test_attr => 1
          end
          has_permission_on :permission_children, :to => :test do
            if_permitted_to :test, :shallow_permissions => :permission
          end
        end
      end
    }
    engine = Authorization::Engine.new(reader)

    perm_data_attr_1 = PermissionMock.new({:test_attr => 1})
    perm_data_attr_2 = PermissionMock.new({:test_attr => 2})
    assert engine.permit?(:test, :context => :permission_children,
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:shallow_permissions =>
                [MockDataObject.new(:permission => perm_data_attr_1)]))
    assert !engine.permit?(:test, :context => :permission_children,
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:shallow_permissions =>
                [MockDataObject.new(:permission => perm_data_attr_2)]))
  end

  def test_attribute_with_permissions_nil
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :test_attr => 1
          end
          has_permission_on :permission_children, :to => :test do
            if_permitted_to :test, :permission
          end
        end
      end
    }
    engine = Authorization::Engine.new(reader)

    assert_nothing_raised do
      engine.permit?(:test, :context => :permission_children,
                :user => MockUser.new(:test_role),
                :object => MockDataObject.new(:permission => nil))
    end
    
    assert !engine.permit?(:test, :context => :permission_children,
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:permission => nil))
  end

  def test_attribute_with_permissions_on_self
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :test_attr => 1
          end
          has_permission_on :permissions, :to => :another_test do
            if_permitted_to :test
          end
        end
      end
    }
    engine = Authorization::Engine.new(reader)

    perm_data_attr_1 = PermissionMock.new({:test_attr => 1})
    perm_data_attr_2 = PermissionMock.new({:test_attr => 2})
    assert engine.permit?(:another_test, :context => :permissions,
              :user => MockUser.new(:test_role),
              :object => perm_data_attr_1)
    assert !engine.permit?(:another_test, :context => :permissions,
              :user => MockUser.new(:test_role),
              :object => perm_data_attr_2)
  end

  def test_attribute_with_permissions_on_self_with_context
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :test_attr => 1
          end
          has_permission_on :permissions, :to => :another_test do
            if_permitted_to :test, :context => :permissions
          end
        end
      end
    }
    engine = Authorization::Engine.new(reader)

    perm_data_attr_1 = PermissionMock.new({:test_attr => 1})
    perm_data_attr_2 = PermissionMock.new({:test_attr => 2})
    assert engine.permit?(:another_test, :context => :permissions,
              :user => MockUser.new(:test_role),
              :object => perm_data_attr_1)
    assert !engine.permit?(:another_test, :context => :permissions,
              :user => MockUser.new(:test_role),
              :object => perm_data_attr_2)
  end

  def test_attribute_with_permissions_and_anded_rules
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :test_attr => 1
          end
          has_permission_on :permission_children, :to => :test, :join_by => :and do
            if_permitted_to :test, :permission
            if_attribute :test_attr => 1
          end
        end
      end
    }
    engine = Authorization::Engine.new(reader)

    perm_data_attr_1 = PermissionMock.new({:test_attr => 1})
    perm_data_attr_2 = PermissionMock.new({:test_attr => 2})
    assert engine.permit?(:test, :context => :permission_children,
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:permission => perm_data_attr_1, :test_attr => 1))
    assert !engine.permit?(:test, :context => :permission_children,
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:permission => perm_data_attr_2, :test_attr => 1))
    assert !engine.permit?(:test, :context => :permission_children,
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:permission => perm_data_attr_1, :test_attr => 2))
  end

  def test_attribute_with_anded_rules
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test, :join_by => :and do
            if_attribute :test_attr => 1
            if_attribute :test_attr_2 => 2
          end
        end
      end
    }
    engine = Authorization::Engine.new(reader)

    assert engine.permit?(:test, :context => :permissions,
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:test_attr => 1, :test_attr_2 => 2))
    assert !engine.permit?(:test, :context => :permissions,
              :user => MockUser.new(:test_role),
              :object => MockDataObject.new(:test_attr => 1, :test_attr_2 => 3))
  end
  
  def test_raise_on_if_attribute_hash_on_collection
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :test_attrs => {:attr => is {1}}
          end
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    assert_raise Authorization::AuthorizationUsageError do
      engine.permit?(:test, :context => :permissions,
                     :user => MockUser.new(:test_role),
                     :object => MockDataObject.new(:test_attrs => [1, 2, 3]))
    end
  end
  
  def test_role_title_description
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role, :title => 'Test Role' do
          description "Test Role Description"
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    assert engine.roles.include?(:test_role)
    assert_equal "Test Role", engine.role_titles[:test_role]
    assert_equal "Test Role", engine.title_for(:test_role)
    assert_nil engine.title_for(:test_role_2)
    assert_equal "Test Role Description", engine.role_descriptions[:test_role]
    assert_equal "Test Role Description", engine.description_for(:test_role)
    assert_nil engine.description_for(:test_role_2)
  end
  
  def test_multithread
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test
        end
      end
    }
    
    engine = Authorization::Engine.new(reader)
    Authorization.current_user = MockUser.new(:test_role)
    assert engine.permit?(:test, :context => :permissions)
    Thread.new do
      Authorization.current_user = MockUser.new(:test_role2)
      assert !engine.permit?(:test, :context => :permissions)
    end
    assert engine.permit?(:test, :context => :permissions)
    Authorization.current_user = nil
  end

  def test_clone
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :attr => { :sub_attr => is { user } }
            if_permitted_to :read, :attr_2 => :attr_3
            if_permitted_to :read, :attr_2
          end
        end
      end
    }

    engine = Authorization::Engine.new(reader)
    cloned_engine = engine.clone
    assert_not_equal engine.auth_rules[0].contexts.object_id,
        cloned_engine.auth_rules[0].contexts.object_id
    assert_not_equal engine.auth_rules[0].attributes[0].send(:instance_variable_get, :@conditions_hash)[:attr].object_id,
        cloned_engine.auth_rules[0].attributes[0].send(:instance_variable_get, :@conditions_hash)[:attr].object_id
  end
end
