require File.dirname(__FILE__) + "/lib/rails_legacy.rb"
require File.dirname(__FILE__) + "/lib/helper.rb"
require File.dirname(__FILE__) + "/lib/in_controller.rb"
require File.dirname(__FILE__) + "/lib/in_model.rb"
require File.dirname(__FILE__) + "/lib/obligation_scope.rb"

min_rails_version = "2.1.0"
if Rails::VERSION::STRING < min_rails_version
  raise "declarative_authorization requires Rails #{min_rails_version}.  You are using #{Rails::VERSION::STRING}."
end

ActionController::Base.send :include, Authorization::AuthorizationInController
ActionController::Base.helper Authorization::AuthorizationHelper

ActiveRecord::Base.send :include, Authorization::AuthorizationInModel