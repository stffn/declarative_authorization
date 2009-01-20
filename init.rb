require File.dirname(__FILE__) + "/lib/helper.rb"
require File.dirname(__FILE__) + "/lib/in_controller.rb"
require File.dirname(__FILE__) + "/lib/in_model.rb"
require File.dirname(__FILE__) + "/lib/obligation_scope.rb"

ActionController::Base.send :include, Authorization::AuthorizationInController
ActionController::Base.helper Authorization::AuthorizationHelper

ActiveRecord::Base.send :include, Authorization::AuthorizationInModel