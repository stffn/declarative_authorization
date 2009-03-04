require File.join(File.dirname(__FILE__), 'test_helper.rb')
require File.join(File.dirname(__FILE__), %w{.. lib declarative_authorization maintenance})

class MaintenanceTest < Test::Unit::TestCase

  def test_usages_by_controllers
    usage_test_controller = Class.new(ActionController::Base)
    usage_test_controller.send(:define_method, :an_action) {}
    usage_test_controller.filter_access_to :an_action

    assert Authorization::Maintenance::Usage::usages_by_controller.
              include?(usage_test_controller)
  end

end