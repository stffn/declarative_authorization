ActionController::Routing::Routes.draw do |map|
  if Authorization::activate_authorization_rules_browser?
    map.resources :authorization_rules, :only => [:index], 
        :collection => {:graph => :get, :change => :get, :suggest_change => :get}
    map.resources :authorization_usages, :only => :index
  end
end