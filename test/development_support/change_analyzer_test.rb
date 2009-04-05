require File.join(File.dirname(__FILE__), %w{.. test_helper.rb})
require File.join(File.dirname(__FILE__), %w{.. .. lib declarative_authorization development_support change_analyzer})


class AuthorizationRulesAnalyzerTest < Test::Unit::TestCase

  def test_advisor_for_adding_permission
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
      # tests to succeed
      assert permit?(:read, :context => :permissions, :user => user_to_extend_permissions)
      assert !permit?(:read, :context => :permissions, :user => another_user)
    end

    assert_equal 1, approaches.length
    assert_equal :role, approaches.first.target_type
    assert_equal :test_role_2, approaches.first.target.to_sym
  end
end
