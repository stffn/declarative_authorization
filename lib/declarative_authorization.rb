require File.join(%w{declarative_authorization helper})
require File.join(%w{declarative_authorization in_controller})
if defined?(ActiveRecord)
  require File.join(%w{declarative_authorization in_model})
  require File.join(%w{declarative_authorization obligation_scope})
end

require File.join(%w{declarative_authorization railsengine}) if defined?(::Rails::Engine)

ActionController::Base.send :include, Authorization::AuthorizationInController
ActionController::Base.helper Authorization::AuthorizationHelper

ActiveRecord::Base.send :include, Authorization::AuthorizationInModel if defined?(ActiveRecord)
