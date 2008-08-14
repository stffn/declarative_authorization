# Authorization::AuthorizationHelper
require File.dirname(__FILE__) + '/authorization.rb'

module Authorization
  module AuthorizationHelper
  
    # If the current user meets the given privilege, permitted_to? returns true
    # and yields to the optional block.  The attribute checks that are defined
    # in the authorization rules are only evaluated if an object is given
    # for context.
    # 
    # Examples:
    #     <% permitted_to? :create, :users do %>
    #     <%= link_to 'New', new_user_path %>
    #     <% end %>
    #     ...
    #     <% if permitted_to? :create, :users %>
    #     <%= link_to 'New', new_user_path %>
    #     <% else %>
    #     You are not allowed to create new users!
    #     <% end %>
    #     ...
    #     <% for user in @users %>
    #     <%= link_to 'Edit', edit_user_path(user) if permitted_to? :update, user %>
    #     <% end %>
    # 
    def permitted_to? (privilege, object_or_sym = nil, &block)
      controller.permitted_to?(privilege, object_or_sym, &block)
    end
  end
end