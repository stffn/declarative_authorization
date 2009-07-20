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
    # To pass in an object and override the context, you can use the optional
    # options:
    #     permitted_to? :update, user, :context => :account
    # 
    def permitted_to? (privilege, object_or_sym = nil, options = {}, &block)
      controller.permitted_to?(privilege, object_or_sym, options, &block)
    end
  
    # While permitted_to? is used for authorization in views, in some cases
    # content should only be shown to some users without being concerned
    # with authorization.  E.g. to only show the most relevant menu options 
    # to a certain group of users.  That is what has_role? should be used for.
    # 
    # Examples:
    #     <% has_role?(:sales) do %>
    #     <%= link_to 'All contacts', contacts_path %>
    #     <% end %>
    #     ...
    #     <% if has_role?(:sales) %>
    #     <%= link_to 'Customer contacts', contacts_path %>
    #     <% else %>
    #     ...
    #     <% end %>
    # 
    def has_role? (*roles, &block)
      controller.has_role?(*roles, &block)
    end
    
    # As has_role? except checks all roles included in the role hierarchy
    def has_role_with_hierarchy?(*roles, &block)
      controller.has_role_with_hierarchy?(*roles, &block)
    end
  end
end