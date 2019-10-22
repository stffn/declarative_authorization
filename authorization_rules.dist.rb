authorization do
  role :guest do
    # add permissions for guests here, e.g.
    # has_permission_on :conferences, :to => :read
  end

  # permissions on other roles, such as
  # role :admin do
  #  has_permission_on :conferences, :to => :manage
  # end
end

privileges do
  # default privilege hierarchies to facilitate RESTful Rails apps
  privilege :manage, includes: %i[create read update delete]
  privilege :read, includes: %i[index show]
  privilege :create, includes: :new
  privilege :update, includes: :edit
  privilege :delete, includes: :destroy
end
