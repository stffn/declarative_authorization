if Authorization::activate_authorization_rules_browser?
  if Rails.respond_to?(:application)
    Rails.application.routes.draw do
      resources :authorization_rules, :only => [:index] do
          collection do
            get :graph
            get :change
            get :suggest_change
          end
      end
      resources :authorization_usages, :only => :index
    end
  else
    ActionController::Routing::Routes.draw do |map|
      map.resources :authorization_rules, :only => [:index],
          :collection => {:graph => :get, :change => :get, :suggest_change => :get}
      map.resources :authorization_usages, :only => :index
    end
  end
end
