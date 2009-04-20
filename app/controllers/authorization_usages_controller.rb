if Authorization::activate_authorization_rules_browser?

require File.join(File.dirname(__FILE__), %w{.. .. lib declarative_authorization maintenance})

class AuthorizationUsagesController < ApplicationController
  unloadable
  
  helper :authorization_rules
  filter_access_to :all, :require => :read
  # TODO set context?

  def index
    respond_to do |format|
      format.html do
        @auth_usages_by_controller = Authorization::Maintenance::Usage.usages_by_controller
      end
    end
  end
end

else
class AuthorizationUsagesController < ApplicationController; end
end # activate_authorization_rules_browser?