require File.join(File.dirname(__FILE__), %w{.. test_helper.rb})
require File.join(File.dirname(__FILE__), %w{.. .. lib declarative_authorization development_support change_supporter})


class ChangeSupporterTest < Test::Unit::TestCase

  def test_adding_permission
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
        end
        role :test_role_2 do
          includes :test_role
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    analyzer = Authorization::DevelopmentSupport::ChangeSupporter.new(engine)

    user_to_extend_permissions = MockUser.new(:test_role_2)
    another_user = MockUser.new(:test_role)

    approaches = analyzer.find_approaches_for(:users => [user_to_extend_permissions, another_user]) do
      assert permit?(:read, :context => :permissions, :user => users.first)
      assert !permit?(:read, :context => :permissions, :user => users[1])
    end

    assert approaches.any? {|approach| approach.steps.any? {|step| step.class == Authorization::DevelopmentSupport::ChangeSupporter::AssignPrivilegeToRoleAction}}
  end

  def test_adding_permission_with_privilege_hierarchy
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
        end
      end
      privileges do
        privilege :manage, :includes => [:create, :read]
      end
    }
    engine = Authorization::Engine.new(reader)
    analyzer = Authorization::DevelopmentSupport::ChangeSupporter.new(engine)

    user_to_extend_permissions = MockUser.new(:test_role)

    approaches = analyzer.find_approaches_for(:users => [user_to_extend_permissions]) do
      assert permit?(:read, :context => :permissions, :user => users.first)
    end

    assert approaches.any? {|approach|
      approach.steps.first.class == Authorization::DevelopmentSupport::ChangeSupporter::AssignPrivilegeToRoleAction and
          approach.steps.first.privilege == :manage
    }
  end

  def test_adding_permission_by_assigning_role
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
        end
        role :test_role_2 do
          has_permission_on :permissions, :to => :read
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    analyzer = Authorization::DevelopmentSupport::ChangeSupporter.new(engine)

    user_to_extend_permissions = MockUser.new(:test_role)
    another_user = MockUser.new(:test_role)

    approaches = analyzer.find_approaches_for(:users => [user_to_extend_permissions, another_user]) do
      assert permit?(:read, :context => :permissions, :user => users.first)
      assert !permit?(:read, :context => :permissions, :user => users[1])
    end

    assert approaches.any? {|approach| approach.changes.first.class == Authorization::DevelopmentSupport::ChangeSupporter::AssignRoleToUserAction}
  end

  def test_adding_permission_by_assigning_role_with_privilege_hierarchy
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :manage
        end
      end
      privileges do
        privilege :manage, :includes => [:create, :read]
      end
    }
    engine = Authorization::Engine.new(reader)
    analyzer = Authorization::DevelopmentSupport::ChangeSupporter.new(engine)

    user_to_extend_permissions = MockUser.new()

    approaches = analyzer.find_approaches_for(:users => [user_to_extend_permissions]) do
      assert permit?(:read, :context => :permissions, :user => users.first)
    end

    assert approaches.any? {|approach| approach.changes.first.class == Authorization::DevelopmentSupport::ChangeSupporter::AssignRoleToUserAction}
  end

  def test_adding_permission_by_assigning_role_many
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
        end
        role :test_role_2 do
          has_permission_on :permissions, :to => :read
        end
        role :irrelevant_test_role_1 do
        end
        role :irrelevant_test_role_2 do
        end
        role :irrelevant_test_role_3 do
        end
        role :irrelevant_test_role_4 do
        end
        role :irrelevant_test_role_5 do
        end
        role :irrelevant_test_role_6 do
        end
        role :irrelevant_test_role_7 do
        end
        role :irrelevant_test_role_8 do
        end
        role :irrelevant_test_role_9 do
        end
        role :irrelevant_test_role_10 do
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    analyzer = Authorization::DevelopmentSupport::ChangeSupporter.new(engine)

    user_to_extend_permissions = MockUser.new(:test_role)
    another_user = MockUser.new(:test_role)

    approaches = analyzer.find_approaches_for(:users => [user_to_extend_permissions, another_user]) do
      assert permit?(:read, :context => :permissions, :user => users.first)
      assert !permit?(:read, :context => :permissions, :user => users[1])
    end

    assert approaches.any? {|approach| approach.changes.first.class == Authorization::DevelopmentSupport::ChangeSupporter::AssignRoleToUserAction}
  end
  
  def test_adding_permission_with_new_role
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    analyzer = Authorization::DevelopmentSupport::ChangeSupporter.new(engine)

    user_to_extend_permissions = MockUser.new(:test_role)
    another_user = MockUser.new(:test_role)

    approaches = analyzer.find_approaches_for(:users => [user_to_extend_permissions, another_user]) do
      assert permit?(:read, :context => :permissions, :user => users.first)
      assert !permit?(:read, :context => :permissions, :user => users[1])
    end

    assert approaches.any? {|approach| approach.changes.first.class == Authorization::DevelopmentSupport::ChangeSupporter::CreateAndAssignRoleToUserAction}
  end

  def test_adding_permission_with_new_role_complex
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :lower_role do
        end
        role :test_role do
          includes :lower_role
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    analyzer = Authorization::DevelopmentSupport::ChangeSupporter.new(engine)

    user_to_extend_permissions = MockUser.new(:test_role)
    another_user = MockUser.new(:test_role)

    approaches = analyzer.find_approaches_for(:users => [another_user, user_to_extend_permissions]) do
      assert permit?(:read, :context => :permissions, :user => users[1])
      assert !permit?(:read, :context => :permissions, :user => users[0])
    end

    assert approaches.any? {|approach| approach.changes.first.class == Authorization::DevelopmentSupport::ChangeSupporter::CreateAndAssignRoleToUserAction}
  end

  def test_adding_permission_with_assigning_role_and_adding_permission
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    analyzer = Authorization::DevelopmentSupport::ChangeSupporter.new(engine)

    user_to_extend_permissions = MockUser.new()

    approaches = analyzer.find_approaches_for(:users => [user_to_extend_permissions]) do
      assert permit?(:read, :context => :permissions, :user => users.first)
    end

    assert_not_equal 0, approaches.length
    assert approaches.any? {|approach| approach.changes.first.class == Authorization::DevelopmentSupport::ChangeSupporter::AddPrivilegeAndAssignRoleToUserAction}
  end

  def test_adding_permission_with_assigning_role_and_adding_permission_with_hierarchy
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :higher_role do
          includes :test_role
        end
        role :test_role do
          has_permission_on :permissions, :to => :manage
        end
      end
      privileges do
        privilege :manage, :includes => [:create, :read]
      end
    }
    engine = Authorization::Engine.new(reader)
    analyzer = Authorization::DevelopmentSupport::ChangeSupporter.new(engine)

    user_to_extend_permissions = MockUser.new

    approaches = analyzer.find_approaches_for(:users => [user_to_extend_permissions]) do
      assert permit?(:read, :context => :permissions, :user => users.first)
    end

    # Don't try to assign any permissions to higher_role, it already has the
    # necessary permissions through the hierarchies
    assert !approaches.any? {|approach|
      approach.steps.first.class == Authorization::DevelopmentSupport::ChangeSupporter::AddPrivilegeAndAssignRoleToUserAction
    }
  end

  def test_removing_permission
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :read
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    analyzer = Authorization::DevelopmentSupport::ChangeSupporter.new(engine)

    user_to_remove_permissions_from = MockUser.new(:test_role)

    approaches = analyzer.find_approaches_for(:users => [user_to_remove_permissions_from]) do
      assert !permit?(:read, :context => :permissions, :user => users.first)
    end

    # either: remove that privilege from :test_role
    assert approaches[0,2].any? {|approach| approach.changes.length == 1 and approach.changes.first.class == Authorization::DevelopmentSupport::ChangeSupporter::RemovePrivilegeFromRoleAction }
    # or: remove that role from the user
    assert approaches[0,2].any? {|approach| approach.changes.length == 1 and approach.changes.first.class == Authorization::DevelopmentSupport::ChangeSupporter::RemoveRoleFromUserAction }
  end

  def test_removing_permission_privilege_hierarchy
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :manage
        end
      end
      privileges do
        privilege :manage, :includes => [:create, :read]
      end
    }
    engine = Authorization::Engine.new(reader)
    analyzer = Authorization::DevelopmentSupport::ChangeSupporter.new(engine)

    user_to_remove_permissions_from = MockUser.new(:test_role)

    approaches = analyzer.find_approaches_for(:users => [user_to_remove_permissions_from]) do
      assert !permit?(:read, :context => :permissions, :user => users.first)
    end

    assert approaches[0,2].any? {|approach| approach.changes.length == 1 and approach.changes.first.class == Authorization::DevelopmentSupport::ChangeSupporter::RemovePrivilegeFromRoleAction }
  end

  def test_removing_permission_with_constraint
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :read do
            if_attribute :attr => "1"
          end
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    analyzer = Authorization::DevelopmentSupport::ChangeSupporter.new(engine)

    user_to_remove_permissions_from = MockUser.new(:test_role)

    approaches = analyzer.find_approaches_for(:users => [user_to_remove_permissions_from]) do
      assert !permit?(:read, :context => :permissions, :user => users.first)
    end

    # either: remove that privilege from :test_role
    assert approaches[0,2].any? {|approach| approach.changes.length == 1 and approach.changes.first.class == Authorization::DevelopmentSupport::ChangeSupporter::RemovePrivilegeFromRoleAction }
    # or: remove that role from the user
    assert approaches[0,2].any? {|approach| approach.changes.length == 1 and approach.changes.first.class == Authorization::DevelopmentSupport::ChangeSupporter::RemoveRoleFromUserAction }
  end

  def test_moving_permission
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role_2 do
        end
        role :test_role do
          has_permission_on :permissions, :to => :read
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    analyzer = Authorization::DevelopmentSupport::ChangeSupporter.new(engine)

    user_to_remove_permissions_from = MockUser.new(:test_role)
    user_to_keep_permission = MockUser.new(:test_role, :test_role_2)

    approaches = analyzer.find_approaches_for(:users => [user_to_remove_permissions_from, user_to_keep_permission]) do
      assert !permit?(:read, :context => :permissions, :user => users.first)
      assert permit?(:read, :context => :permissions, :user => users[1])
    end
    
    assert approaches.any? {|approach| approach.steps.find {|step| step.class == Authorization::DevelopmentSupport::ChangeSupporter::RemovePrivilegeFromRoleAction}}
    assert approaches.any? {|approach| approach.steps.find {|step| step.class == Authorization::DevelopmentSupport::ChangeSupporter::AssignPrivilegeToRoleAction}}
  end

  def test_removing_permission_adding_role
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :read
          has_permission_on :permissions_2, :to => :read
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    analyzer = Authorization::DevelopmentSupport::ChangeSupporter.new(engine)

    user_to_remove_permissions_from = MockUser.new(:test_role)
    user_to_keep_permission = MockUser.new(:test_role)

    approaches = analyzer.find_approaches_for(:users => [user_to_remove_permissions_from, user_to_keep_permission]) do
      assert !permit?(:read, :context => :permissions, :user => users.first)
      assert permit?(:read, :context => :permissions_2, :user => users.first)
      assert permit?(:read, :context => :permissions, :user => users[1])
      assert permit?(:read, :context => :permissions_2, :user => users[1])
    end

    # solution: add a new role
    assert approaches.any? {|approach| approach.users.first.role_symbols.include?(:test_role) }
  end

  def test_removing_user_role_assignment
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :read
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    analyzer = Authorization::DevelopmentSupport::ChangeSupporter.new(engine)

    user_to_remove_permissions_from = MockUser.new(:test_role)
    user_to_keep_permission = MockUser.new(:test_role)

    approaches = analyzer.find_approaches_for(:users => [user_to_remove_permissions_from, user_to_keep_permission]) do
      assert !permit?(:read, :context => :permissions, :user => users.first)
      assert permit?(:read, :context => :permissions, :user => users[1])
    end

    # solutions: remove user-role assignment for first user
    assert approaches.any? {|approach| approach.users.first.role_symbols.empty? }
  end

  def test_removing_user_role_assignment_hierarchy
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :higher_role do
          includes :test_role
        end
        role :test_role do
          has_permission_on :permissions, :to => :read
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    analyzer = Authorization::DevelopmentSupport::ChangeSupporter.new(engine)

    user_to_remove_permissions_from = MockUser.new(:higher_role)
    user_to_keep_permission = MockUser.new(:higher_role)

    approaches = analyzer.find_approaches_for(:users => [user_to_remove_permissions_from, user_to_keep_permission]) do
      assert !permit?(:read, :context => :permissions, :user => users.first)
      assert permit?(:read, :context => :permissions, :user => users[1])
    end

    # solutions: remove user-role assignment for first user
    assert approaches.any? {|approach| !approach.users.first.role_symbols.include?(:higher_role) }
  end

  def test_removing_user_role_assignment_many
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :read
        end
        role :irrelevant_test_role_1 do
        end
        role :irrelevant_test_role_2 do
        end
        role :irrelevant_test_role_3 do
        end
        role :irrelevant_test_role_4 do
        end
        role :irrelevant_test_role_5 do
        end
        role :irrelevant_test_role_6 do
        end
        role :irrelevant_test_role_7 do
        end
        role :irrelevant_test_role_8 do
        end
        role :irrelevant_test_role_9 do
        end
        role :irrelevant_test_role_10 do
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    analyzer = Authorization::DevelopmentSupport::ChangeSupporter.new(engine)

    roles = [:test_role] + (1..10).collect {|i| :"irrelevant_test_role_#{i}"}
    user_to_remove_permissions_from = MockUser.new(*roles)
    user_to_keep_permission = MockUser.new(*roles.clone)

    approaches = analyzer.find_approaches_for(:users => [user_to_remove_permissions_from, user_to_keep_permission]) do
      assert !permit?(:read, :context => :permissions, :user => users.first)
      assert permit?(:read, :context => :permissions, :user => users[1])
    end

    # solutions: remove user-role assignment for first user
    assert approaches.any? {|approach| !approach.users.first.role_symbols.include?(:test_role) }
  end

  def test_no_superset_approaches
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :read
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    analyzer = Authorization::DevelopmentSupport::ChangeSupporter.new(engine)

    user_to_remove_permission_from = MockUser.new(:test_role)
    user_to_remove_permission_from_2 = MockUser.new(:test_role)

    approaches = analyzer.find_approaches_for(:users => [user_to_remove_permission_from, user_to_remove_permission_from_2]) do
      assert !permit?(:read, :context => :permissions, :user => users.first)
      assert !permit?(:read, :context => :permissions, :user => users[1])
    end

    assert !approaches.any? {|approach|
      approach.steps.any? {|step| step.class == Authorization::DevelopmentSupport::ChangeSupporter::RemoveRoleFromUserAction} and
      approach.steps.any? {|step| step.class == Authorization::DevelopmentSupport::ChangeSupporter::RemovePrivilegeFromRoleAction}
    }
  end

  def test_prohibited_actions_role_to_user
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :read
        end
        role :test_role_2 do
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    analyzer = Authorization::DevelopmentSupport::ChangeSupporter.new(engine)

    user_to_extend_permissions = MockUser.new(:test_role_2)

    approaches = analyzer.find_approaches_for(:users => [user_to_extend_permissions],
                    :prohibited_actions => [[:assign_role_to_user, :test_role, user_to_extend_permissions.login]]) do #, 'other_attendee'
      assert permit?(:read, :context => :permissions, :user => users.first)
    end

    assert_not_equal 0, approaches.length
    assert !approaches.any? {|approach| approach.steps.any? {|step| step.class == Authorization::DevelopmentSupport::ChangeSupporter::AssignRoleToUserAction}}
  end

  def test_prohibited_actions_role_to_any_user
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :read
        end
        role :test_role_2 do
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    analyzer = Authorization::DevelopmentSupport::ChangeSupporter.new(engine)

    user_to_extend_permissions = MockUser.new(:test_role_2)

    approaches = analyzer.find_approaches_for(:users => [user_to_extend_permissions],
                    :prohibited_actions => [[:assign_role_to_user, :test_role]]) do
      assert permit?(:read, :context => :permissions, :user => users.first)
    end

    assert_not_equal 0, approaches.length
    assert !approaches.any? {|approach| approach.steps.any? {|step| step.class == Authorization::DevelopmentSupport::ChangeSupporter::AssignRoleToUserAction and step.role == :test_role }}
  end

  def test_prohibited_actions_permission_to_role
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :read
        end
        role :test_role_2 do
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    analyzer = Authorization::DevelopmentSupport::ChangeSupporter.new(engine)

    user_to_extend_permissions = MockUser.new(:test_role_2)

    approaches = analyzer.find_approaches_for(:users => [user_to_extend_permissions],
                    :prohibited_actions => [[:add_privilege, :read, :permissions, :test_role_2]]) do #, 'other_attendee'
      assert permit?(:read, :context => :permissions, :user => users.first)
    end

    assert_not_equal 0, approaches.length
    assert !approaches.any? {|approach| approach.steps.any? {|step| step.class == Authorization::DevelopmentSupport::ChangeSupporter::AssignPrivilegeToRoleAction}}
  end

  def test_prohibited_actions_remove_role
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :read
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    analyzer = Authorization::DevelopmentSupport::ChangeSupporter.new(engine)

    user_to_remove_permission = MockUser.new(:test_role)

    approaches = analyzer.find_approaches_for(:users => [user_to_remove_permission],
                    :prohibited_actions => [[:remove_role_from_user, :test_role, user_to_remove_permission.login]]) do
      assert !permit?(:read, :context => :permissions, :user => users.first)
    end

    assert_not_equal 0, approaches.length
    assert !approaches.any? {|approach| approach.steps.any? {|step| step.class == Authorization::DevelopmentSupport::ChangeSupporter::RemoveRoleFromUserAction}}
  end

  def test_affected_users
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
        end
        role :test_role_2 do
          includes :test_role
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    analyzer = Authorization::DevelopmentSupport::ChangeSupporter.new(engine)

    user_to_extend_permissions = MockUser.new(:test_role_2)
    another_user = MockUser.new(:test_role)
    all_users = [user_to_extend_permissions, another_user]

    approaches = analyzer.find_approaches_for(:users => all_users) do
      assert permit?(:read, :context => :permissions, :user => users[0])
      assert !permit?(:read, :context => :permissions, :user => users[1])
    end

    assert approaches.any? {|approach|
        approach.steps.any? {|step| step.class == Authorization::DevelopmentSupport::ChangeSupporter::AssignPrivilegeToRoleAction} &&
          approach.affected_users(engine, all_users, :read, :permissions).length == 1 }
  end

  def test_affected_users_with_user_change
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
        end
        role :test_role_2 do
          has_permission_on :permissions, :to => :read
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    analyzer = Authorization::DevelopmentSupport::ChangeSupporter.new(engine)

    user_to_extend_permissions = MockUser.new(:test_role)
    another_user = MockUser.new(:test_role)
    all_users = [user_to_extend_permissions, another_user]

    approaches = analyzer.find_approaches_for(:users => all_users) do
      assert permit?(:read, :context => :permissions, :user => users.first)
      assert !permit?(:read, :context => :permissions, :user => users[1])
    end

    assert approaches.any? {|approach|
        approach.changes.first.class == Authorization::DevelopmentSupport::ChangeSupporter::AssignRoleToUserAction &&
            approach.affected_users(engine, all_users, :read, :permissions).length == 1 }
  end

  def test_group_approaches
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          includes :test_role_2
        end
        role :test_role_2 do
          has_permission_on :permissions, :to => :read
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    analyzer = Authorization::DevelopmentSupport::ChangeSupporter.new(engine)

    user_to_extend_permissions = MockUser.new()
    another_user = MockUser.new()
    all_users = [user_to_extend_permissions, another_user]

    approaches = analyzer.find_approaches_for(:users => all_users) do
      assert permit?(:read, :context => :permissions, :user => users.first)
    end

    assert approaches.first.similar_to(approaches[1]),
        "First two approaches should be similar"

    grouped_approaches = analyzer.group_approaches(approaches)
    assert_equal 2, grouped_approaches.length
    assert grouped_approaches.first.approach
    assert_equal 1, grouped_approaches.first.similar_approaches.length
  end
end
