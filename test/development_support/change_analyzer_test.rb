require File.join(File.dirname(__FILE__), %w{.. test_helper.rb})
require File.join(File.dirname(__FILE__), %w{.. .. lib declarative_authorization development_support change_analyzer})


class ChangeAnalyzerTest < Test::Unit::TestCase

  # TODO further tests
  # * more than one new role, privilege necessary
  #

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
    analyzer = Authorization::DevelopmentSupport::ChangeAnalyzer.new(engine)

    user_to_extend_permissions = MockUser.new(:test_role_2)
    another_user = MockUser.new(:test_role)

    approaches = analyzer.find_approaches_for(:add, :permission, :on => :permissions,
        :to => :read, :users => [user_to_extend_permissions, another_user]) do
      assert permit?(:read, :context => :permissions, :user => users.first)
      assert !permit?(:read, :context => :permissions, :user => users[1])
    end

    #approaches.each {|approach| p approach}
    assert approaches.any? {|approach| approach.steps.any? {|step| step.first == :add_privilege and step.last.to_sym == :test_role_2}}
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
    analyzer = Authorization::DevelopmentSupport::ChangeAnalyzer.new(engine)

    user_to_extend_permissions = MockUser.new(:test_role)
    another_user = MockUser.new(:test_role)

    approaches = analyzer.find_approaches_for(:add, :permission, :on => :permissions,
        :to => :read, :users => [user_to_extend_permissions, another_user]) do
      assert permit?(:read, :context => :permissions, :user => users.first)
      assert !permit?(:read, :context => :permissions, :user => users[1])
    end

    assert_not_equal 0, approaches.length
    #assert_equal :role, approaches.first.target_type
    #assert_equal :test_role_2, approaches.first.target.to_sym
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
    analyzer = Authorization::DevelopmentSupport::ChangeAnalyzer.new(engine)

    user_to_extend_permissions = MockUser.new(:test_role)
    another_user = MockUser.new(:test_role)

    approaches = analyzer.find_approaches_for(:add, :permission, :on => :permissions,
        :to => :read, :users => [user_to_extend_permissions, another_user]) do
      assert permit?(:read, :context => :permissions, :user => users.first)
      assert !permit?(:read, :context => :permissions, :user => users[1])
    end

    assert_not_equal 0, approaches.length
    #assert_equal :role, approaches.first.target_type
    #assert_equal :test_role_2, approaches.first.target.to_sym
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
    analyzer = Authorization::DevelopmentSupport::ChangeAnalyzer.new(engine)

    user_to_extend_permissions = MockUser.new(:test_role)
    another_user = MockUser.new(:test_role)

    approaches = analyzer.find_approaches_for(:add, :permission, :on => :permissions,
        :to => :read, :users => [another_user, user_to_extend_permissions]) do
      assert permit?(:read, :context => :permissions, :user => users[1])
      assert !permit?(:read, :context => :permissions, :user => users[0])
    end

    assert_not_equal 0, approaches.length
    #assert_equal :role, approaches.first.target_type
    #assert_equal :test_role_2, approaches.first.target.to_sym
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
    analyzer = Authorization::DevelopmentSupport::ChangeAnalyzer.new(engine)

    user_to_remove_permissions_from = MockUser.new(:test_role)

    approaches = analyzer.find_approaches_for(:remove, :permission, :on => :permissions,
        :to => :read, :users => [user_to_remove_permissions_from]) do
      assert !permit?(:read, :context => :permissions, :user => users.first)
    end

    # either: remove that privilege from :test_role
    assert approaches[0,2].any? {|approach| approach.changes.length == 1 and approach.changes.first.first == :remove_privilege }
    # or: remove that role from the user
    assert approaches[0,2].any? {|approach| approach.changes.length == 1 and approach.changes.first.first == :remove_role_from_user }
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
    analyzer = Authorization::DevelopmentSupport::ChangeAnalyzer.new(engine)

    user_to_remove_permissions_from = MockUser.new(:test_role)
    user_to_keep_permission = MockUser.new(:test_role, :test_role_2)

    approaches = analyzer.find_approaches_for(:remove, :permission, :on => :permissions,
          :to => :read, :users => [user_to_remove_permissions_from, user_to_keep_permission]) do
      assert !permit?(:read, :context => :permissions, :user => users.first)
      assert permit?(:read, :context => :permissions, :user => users[1])
    end
    
    assert approaches.find {|approach| approach.steps.find {|step| step.first == :remove_privilege}}
    assert approaches.find {|approach| approach.steps.find {|step| step.first == :add_privilege}}
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
    analyzer = Authorization::DevelopmentSupport::ChangeAnalyzer.new(engine)

    user_to_remove_permissions_from = MockUser.new(:test_role)
    user_to_keep_permission = MockUser.new(:test_role)

    approaches = analyzer.find_approaches_for(:remove, :permission, :on => :permissions,
        :to => :read, :users => [user_to_remove_permissions_from, user_to_keep_permission]) do
      assert !permit?(:read, :context => :permissions, :user => users.first)
      assert permit?(:read, :context => :permissions_2, :user => users.first)
      assert permit?(:read, :context => :permissions, :user => users[1])
      assert permit?(:read, :context => :permissions_2, :user => users[1])
    end

    # solution: add a new role
    assert_not_equal 0, approaches.length
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
    analyzer = Authorization::DevelopmentSupport::ChangeAnalyzer.new(engine)

    user_to_remove_permissions_from = MockUser.new(:test_role)
    user_to_keep_permission = MockUser.new(:test_role)

    approaches = analyzer.find_approaches_for(:remove, :permission, :on => :permissions,
        :to => :read, :users => [user_to_remove_permissions_from, user_to_keep_permission]) do
      assert !permit?(:read, :context => :permissions, :user => users.first)
      assert permit?(:read, :context => :permissions, :user => users[1])
    end

    # solutions: remove user-role assignment for first user
    assert_not_equal 0, approaches.length
    assert approaches.any? {|approach| approach.users.first.role_symbols.empty? }
  end
end
