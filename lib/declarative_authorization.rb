require File.join(%w{declarative_authorization rails_legacy})
require File.join(%w{declarative_authorization helper})
require File.join(%w{declarative_authorization in_controller})
if defined?(ActiveRecord)
  require File.join(%w{declarative_authorization in_model})
  require File.join(%w{declarative_authorization obligation_scope})
end

min_rails_version = "2.1.0"
if Rails::VERSION::STRING < min_rails_version
  raise "declarative_authorization requires Rails #{min_rails_version}.  You are using #{Rails::VERSION::STRING}."
end

require File.join(%w{declarative_authorization railsengine}) if defined?(::Rails::Engine)

require "action_controller"
ActionController::Base.send :include, Authorization::AuthorizationInController
ActionController::Base.helper Authorization::AuthorizationHelper

ActiveRecord::Base.send :include, Authorization::AuthorizationInModel if defined?(ActiveRecord)
