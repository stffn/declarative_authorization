ActionController::Routing::Routes.draw do |map|
  map.resources :authorization_rules, :only => :index, :collection => {:graph => :get}
  #map.connect 'authorization_rules/:action.:format', :controller => 'authorization_rules'
end