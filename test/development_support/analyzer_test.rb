require File.join(File.dirname(__FILE__), %w{.. test_helper.rb})

auth_analyzer_loadable = false
begin
  require File.join(File.dirname(__FILE__), %w{.. .. lib declarative_authorization development_support analyzer})
  auth_analyzer_loadable = true
rescue
  puts "Could not load Authorization::DevelopmentSupport::Analyzer.  Disabling AuthorizationRulesAnalyzerTest."
end

if auth_analyzer_loadable

class AuthorizationRulesAnalyzerTest < Test::Unit::TestCase

  def test_analyzing_complex_rules
    assert_nothing_raised do
      engine, analyzer = engine_analyzer_for %{
        authorization do
          role :guest do
            has_permission_on :conferences, :to => :read do
              if_attribute :published => true
            end
            has_permission_on :talks, :to => :read do
              if_permitted_to :read, :conference
            end
            has_permission_on :users, :to => :create
            has_permission_on :authorization_rules, :to => :read
            has_permission_on :authorization_usages, :to => :read
          end

          role :user do
            includes :guest
            has_permission_on :conference_attendees, :to => :create do
              if_attribute :user => is {user},
                :conference => { :published => true }
            end
            has_permission_on :conference_attendees, :to => :delete do
              if_attribute :user => is {user},
                :conference => { :attendees => contains {user} }
            end
            has_permission_on :talk_attendees, :to => :create do
              if_attribute :talk => { :conference => { :attendees => contains {user} }}
            end
            has_permission_on :talk_attendees, :to => :delete do
              if_attribute :user => is {user}
            end
          end

          role :conference_organizer do
            has_permission_on :conferences do
              to :manage
              # if...
            end
            has_permission_on [:conference_attendees, :talks, :talk_attendees], :to => :manage
          end

          role :admin do
            has_permission_on [:conferences, :users, :talks], :to => :manage
            has_permission_on :authorization_rules, :to => :read
            has_permission_on :authorization_usages, :to => :read
          end
        end

        privileges do
          privilege :manage, :includes => [:create, :read, :update, :delete]
          privilege :read, :includes => [:index, :show]
          privilege :create, :includes => :new
          privilege :update, :includes => :edit
          privilege :delete, :includes => :destroy
        end
      }
    end
  end

  def test_mergeable_rules_without_constraints
    engine, analyzer = engine_analyzer_for %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test
          has_permission_on :permissions, :to => :test2
        end
      end
    }

    reports = analyzer.reports.select {|rpt| rpt.type == :mergeable_rules}
    assert !reports.empty?
    assert reports.find {|report| report.line == 4}
  end

  def test_mergeable_rules_with_in_block_to
    assert_nothing_raised do
      engine, analyzer = engine_analyzer_for %{
        authorization do
          role :test_role do
            has_permission_on :permissions do
              to :test
            end
          end
        end
      }
    end
  end

  def test_no_mergeable_rules_with_constraints
    engine, analyzer = engine_analyzer_for %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :some_attr => is {bla}
          end
          has_permission_on :permissions, :to => :test2 do
            if_attribute :some_attr_2 => is {bla}
          end
        end
      end
    }

    assert !analyzer.reports.find {|report| report.type == :mergeable_rules}
  end

  def test_no_mergeable_rules_with_if_permitted_to
    engine, analyzer = engine_analyzer_for %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test do
            if_attribute :some_attr => is {bla}
          end
          has_permission_on :permissions, :to => :test2 do
            if_attribute :some_attr => is {bla}
            if_permitted_to :read, :bla
          end
        end
      end
    }

    assert !analyzer.reports.find {|report| report.type == :mergeable_rules}
  end

  def test_role_explosion
    engine, analyzer = engine_analyzer_for %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test
          has_permission_on :permissions, :to => :test2
        end
        role :test_role_2 do
          has_permission_on :permissions, :to => :test
          has_permission_on :permissions, :to => :test2
          has_permission_on :permissions, :to => :test3
          has_permission_on :permissions, :to => :test4
        end
        role :test_role_3 do
          has_permission_on :permissions, :to => :test
          has_permission_on :permissions, :to => :test2
        end
      end
    }

    report = analyzer.reports.find {|rpt| rpt.type == :role_explosion}
    assert report
    assert_nil report.line
  end

  def test_inheriting_privileges
    engine, analyzer = engine_analyzer_for %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => [:test, :test_2]
          has_permission_on :other_permissions, :to => [:test, :test_3]
        end
      end
      privileges do
        privilege :test, :includes => :test_2
      end
    }

    reports = analyzer.reports.select {|report| report.type == :inheriting_privileges}
    assert_equal 1, reports.length
    assert_equal 4, reports.first.line
  end

  def test_privileges_rules
    engine, analyzer = engine_analyzer_for %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => [:test, :test_2]
          has_permission_on :other_permissions, :to => :test
          has_permission_on :other_permissions_2, :to => :test_2
        end
      end
    }

    priv = Authorization::DevelopmentSupport::AnalyzerEngine::Privilege.for_sym(:test, engine)
    assert_equal 2, priv.rules.length
  end

  def test_relevant_roles
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
        end
        role :test_role_2 do
          includes :test_role
        end
        role :test_role_3 do
        end
        role :test_role_4 do
        end
        role :irrelevant_role do
        end
      end
    }
    engine = Authorization::Engine.new(reader)

    users = [MockUser.new(:test_role_2, :test_role_3), MockUser.new(:test_role_4)]
    relevant_roles = Authorization::DevelopmentSupport::AnalyzerEngine.relevant_roles(engine, users)
    assert_equal 4, relevant_roles.length
  end

  def test_roles_for_privilege
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :higher_role do
          includes :lower_role
        end
        role :lower_role do
          has_permission_on :test_2, :to => :read
        end
        role :test_role do
          has_permission_on :test, :to => :read
        end
        role :irrelevant_role_1 do
        end
        role :irrelevant_role_2 do
        end
        role :irrelevant_role_3 do
        end
      end
    }
    engine = Authorization::Engine.new(reader)

    assert_equal 1, Authorization::DevelopmentSupport::AnalyzerEngine::Role.all_for_privilege(:read, :test, engine).length
    assert_equal 2, Authorization::DevelopmentSupport::AnalyzerEngine::Role.all_for_privilege(:read, :test_2, engine).length
  end

  def test_analyze_for_proposed_privilege_hierarchy
    engine, analyzer = engine_analyzer_for %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => [:test, :test_2]
          has_permission_on :other_permissions_2, :to => :test_2
        end
        role :test_role_2 do
          has_permission_on :permissions, :to => [:test, :test_2]
          has_permission_on :other_permissions, :to => :test_3
        end
      end
    }

    reports = analyzer.reports.select {|report| report.type == :proposed_privilege_hierarchy}
    assert_equal 1, reports.length
    assert_equal 4, reports.first.line
  end

  protected
  def engine_analyzer_for (rules)
    reader = Authorization::Reader::DSLReader.new
    reader.parse rules
    engine = Authorization::Engine.new(reader)

    analyzer = Authorization::DevelopmentSupport::Analyzer.new(engine)
    analyzer.analyze rules

    [engine, analyzer]
  end
end

end # Authorization::Analyzer was loaded