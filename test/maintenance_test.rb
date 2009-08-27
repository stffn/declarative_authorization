require File.join(File.dirname(__FILE__), 'test_helper.rb')
require File.join(File.dirname(__FILE__), %w{.. lib declarative_authorization maintenance})

class MaintenanceTest < Test::Unit::TestCase
  include Authorization::TestHelper

  def test_usages_by_controllers
    usage_test_controller = Class.new(ActionController::Base)
    usage_test_controller.send(:define_method, :an_action) {}
    usage_test_controller.filter_access_to :an_action

    assert Authorization::Maintenance::Usage::usages_by_controller.
              include?(usage_test_controller)
  end

  def test_without_access_control
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :permissions, :to => :test
        end
      end
    }
    engine = Authorization::Engine.new(reader)
    assert !engine.permit?(:test_2, :context => :permissions,
        :user => MockUser.new(:test_role))
    Authorization::Maintenance::without_access_control do
      assert engine.permit!(:test_2, :context => :permissions,
          :user => MockUser.new(:test_role))
    end
    without_access_control do
      assert engine.permit?(:test_2, :context => :permissions,
          :user => MockUser.new(:test_role))
    end
    Authorization::Maintenance::without_access_control do
      Authorization::Maintenance::without_access_control do
        assert engine.permit?(:test_2, :context => :permissions,
            :user => MockUser.new(:test_role))
      end
      assert engine.permit?(:test_2, :context => :permissions,
          :user => MockUser.new(:test_role))
    end
  end

end