require File.join(File.dirname(__FILE__), 'test_helper.rb')
require File.join(File.dirname(__FILE__), %w{.. lib declarative_authorization authorization_rules_analyzer})

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

    report = analyzer.reports.find {|report| report.type == :mergeable_rules}
    assert report
    assert_equal 4, report.line
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

  protected
  def engine_analyzer_for (rules)
    reader = Authorization::Reader::DSLReader.new
    reader.parse rules
    engine = Authorization::Engine.new(reader)

    analyzer = Authorization::Analyzer.new(engine)
    analyzer.analyze rules

    [engine, analyzer]
  end
end