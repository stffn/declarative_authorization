require File.join(File.dirname(__FILE__), 'test_helper.rb')

class DSLReaderTest < Test::Unit::TestCase
  def test_privileges
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      privileges do
        privilege :test_priv do
          includes :lower_priv
        end
      end
    }
    assert_equal 2, reader.privileges_reader.privileges.length
    assert_equal [[:lower_priv, nil]], 
      reader.privileges_reader.privilege_hierarchy[:test_priv]
  end
  
  def test_privileges_with_context
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      privileges do
        privilege :test_priv, :test_context do
          includes :lower_priv
        end
      end
    }
    assert_equal [[:lower_priv, :test_context]], 
      reader.privileges_reader.privilege_hierarchy[:test_priv]
  end
  
  def test_privileges_one_line
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      privileges do
        privilege :test_priv, :test_context, :includes => :lower_priv
        privilege :test_priv_2, :test_context, :includes => [:lower_priv]
        privilege :test_priv_3, :includes => [:lower_priv]
      end
    }
    assert_equal [[:lower_priv, :test_context]], 
      reader.privileges_reader.privilege_hierarchy[:test_priv]
    assert_equal [[:lower_priv, :test_context]], 
      reader.privileges_reader.privilege_hierarchy[:test_priv_2]
    assert_equal [[:lower_priv, nil]], 
      reader.privileges_reader.privilege_hierarchy[:test_priv_3]
  end
  
  def test_auth_role
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          includes :lesser_role
          has_permission_on :items, :to => :read
        end
      end
    }
    assert_equal 1, reader.auth_rules_reader.roles.length
    assert_equal [:lesser_role], reader.auth_rules_reader.role_hierarchy[:test_role]
    assert_equal 1, reader.auth_rules_reader.auth_rules.length
  end
  
  def test_auth_role_permit_on
    reader = Authorization::Reader::DSLReader.new
    reader.parse %|
      authorization do
        role :test_role do
          has_permission_on :test_context do
            to :test_perm, :manage
            if_attribute :test_attr => is { user.test_attr }
          end
        end
      end
    |
    assert_equal 1, reader.auth_rules_reader.roles.length
    assert_equal 1, reader.auth_rules_reader.auth_rules.length
    assert reader.auth_rules_reader.auth_rules[0].matches?(:test_role, [:test_perm], :test_context)
    assert reader.auth_rules_reader.auth_rules[0].matches?(:test_role, [:manage], :test_context)
  end
  
  def test_permit_block
    reader = Authorization::Reader::DSLReader.new
    reader.parse %|
      authorization do
        role :test_role do
          has_permission_on :perms, :to => :test do
            if_attribute :test_attr   => is { user.test_attr }
            if_attribute :test_attr_2 => is_not { user.test_attr }
            if_attribute :test_attr_3 => contains { user.test_attr }
            if_attribute :test_attr_4 => does_not_contain { user.test_attr }
            if_attribute :test_attr_5 => is_in { user.test_attr }
            if_attribute :test_attr_5 => is_not_in { user.test_attr }
          end
        end
      end
    |
    assert_equal 1, reader.auth_rules_reader.roles.length
    assert_equal 1, reader.auth_rules_reader.auth_rules.length
    assert reader.auth_rules_reader.auth_rules[0].matches?(:test_role, [:test], :perms)
  end
  
  def test_has_permission_to_with_context
    reader = Authorization::Reader::DSLReader.new
    reader.parse %|
      authorization do
        role :test_role do
          has_permission_on :perms, :to => :test
        end
      end
    |
    assert_equal 1, reader.auth_rules_reader.roles.length
    assert_equal 1, reader.auth_rules_reader.auth_rules.length
    assert reader.auth_rules_reader.auth_rules[0].matches?(:test_role, [:test], :perms)
  end
  
  def test_context
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      contexts do
        context :high_level_context do
          includes :low_level_context_1, :low_level_context_2
        end
      end
    }
  end
  
  def test_dsl_error
    reader = Authorization::Reader::DSLReader.new
    assert_raise(Authorization::Reader::DSLError) do
      reader.parse %{
        authorization do
          includes :lesser_role
        end
      }
    end
  end
  
  def test_syntax_error
    reader = Authorization::Reader::DSLReader.new
    assert_raise(Authorization::Reader::DSLSyntaxError) do
      reader.parse %{
        authorizations do
        end
      }
    end
  end
  
  def test_syntax_error_2
    reader = Authorization::Reader::DSLReader.new
    assert_raise(Authorization::Reader::DSLSyntaxError) do
      reader.parse %{
        authorizations
        end
      }
    end
  end
end
