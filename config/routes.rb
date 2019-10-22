if Authorization.activate_authorization_rules_browser?
  Rails.application.routes.draw do
    resources :authorization_rules, only: [:index] do
      collection do
        get :graph
        get :change
        get :suggest_change
      end
    end
    resources :authorization_usages, only: :index
  end
end
