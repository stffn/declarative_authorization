if Authorization::activate_authorization_rules_browser?

require File.join(File.dirname(__FILE__), %w{.. .. lib declarative_authorization development_support analyzer})
require File.join(File.dirname(__FILE__), %w{.. .. lib declarative_authorization development_support change_supporter})

begin
  # for nice auth_rules output:
  require "parse_tree"
  require "parse_tree_extensions"
  require "ruby2ruby"
rescue LoadError; end

class AuthorizationRulesController < ApplicationController
  unloadable
  
  filter_access_to :all, :require => :read
  def index
    respond_to do |format|
      format.html do
        @auth_rules_script = File.read("#{RAILS_ROOT}/config/authorization_rules.rb")
      end
    end
  end

  def graph
    if params[:format] == "svg"
      render :text => dot_to_svg(auth_to_dot(graph_options)),
          :content_type => "image/svg+xml"
    end
  end

  def change
    @users = find_all_users
    @users.sort! {|a, b| a.login <=> b.login }
    
    @privileges = authorization_engine.auth_rules.collect {|rule| rule.privileges.to_a}.flatten.uniq
    @privilege = params[:privilege].to_sym rescue @privileges.first
    @contexts = authorization_engine.auth_rules.collect {|rule| rule.contexts.to_a}.flatten.uniq
    @context = params[:context].to_sym rescue @contexts.first

    respond_to do |format|
      format.html
      format.js do
        render :partial => 'change'
      end
    end
  end

  def suggest_change
    users_permission = params[:user].inject({}) do |memo, (user_id, data)|
      if data[:permission] != "undetermined"
        begin
          memo[find_user_by_id(user_id)] = (data[:permission] == 'yes')
        rescue ActiveRecord::NotFound
        end
      end
      memo
    end

    prohibited_actions = (params[:prohibited_action] || []).collect do |spec|
      deserialize_changes(spec).flatten
    end

    users_keys = users_permission.keys
    analyzer = Authorization::DevelopmentSupport::ChangeSupporter.new(authorization_engine)
    
    privilege = params[:privilege].to_sym
    context = params[:context].to_sym
    @context = context
    @approaches = analyzer.find_approaches_for(:users => users_keys, :prohibited_actions => prohibited_actions) do
      users.each_with_index do |user, idx|
        args = [privilege, {:context => context, :user => user}]
        assert(users_permission[users_keys[idx]] ? permit?(*args) : !permit?(*args))
      end
    end

    respond_to do |format|
      format.js do
        render :partial => 'suggestions'
      end
    end
  end

  private
  def auth_to_dot (options = {})
    options = {
      :effective_role_privs => true,
      :privilege_hierarchy => false,
      :stacked_roles => false,
      :only_relevant_contexts => true,
      :only_relevant_roles => false,
      :filter_roles => nil,
      :filter_contexts => nil,
      :highlight_privilege => nil,
      :changes => nil,
      :users => nil
    }.merge(options)

    @has_changes = options[:changes] && !options[:changes].empty?
    @highlight_privilege = options[:highlight_privilege]
    @stacked_roles = options[:stacked_roles]

    @users = options[:users]

    engine = authorization_engine.clone
    @changes = replay_changes(engine, @users, options[:changes]) if options[:changes]

    options[:filter_roles] ||= @users.collect {|user| user.role_symbols}.flatten.uniq if options[:only_relevant_roles] and @users

    filter_roles_flattened = nil
    if options[:filter_roles]
      filter_roles_flattened = options[:filter_roles].collect do |role_sym|
        Authorization::DevelopmentSupport::AnalyzerEngine::Role.for_sym(role_sym, engine).
            ancestors.map(&:to_sym) + [role_sym]
      end.flatten.uniq
    end

    @roles = engine.roles
    @roles = @roles.select {|r| filter_roles_flattened.include?(r) } if options[:filter_roles]
    @role_hierarchy = engine.role_hierarchy
    @privilege_hierarchy = engine.privilege_hierarchy
    
    @contexts = engine.auth_rules.
                    collect {|ar| ar.contexts.to_a}.flatten.uniq
    @contexts = @contexts.select {|c| c == options[:filter_contexts] } if options[:filter_contexts]
    @context_privs = {}
    @role_privs = {}
    engine.auth_rules.each do |auth_rule|
      @role_privs[auth_rule.role] ||= []
      auth_rule.contexts.
            select {|c| options[:filter_contexts].nil? or c == options[:filter_contexts]}.
            each do |context|
        @context_privs[context] ||= []
        @context_privs[context] += auth_rule.privileges.to_a
        @context_privs[context].uniq!
        @role_privs[auth_rule.role] += auth_rule.privileges.collect {|p| [context, p, auth_rule.attributes.empty?, auth_rule.to_long_s]}
      end
    end

    if options[:effective_role_privs]
      @roles.each do |role|
        role = Authorization::DevelopmentSupport::AnalyzerEngine::Role.for_sym(role, engine)
        @role_privs[role.to_sym] ||= []
        role.ancestors.each do |lower_role|
          @role_privs[role.to_sym].concat(@role_privs[lower_role.to_sym]).uniq!
        end
      end
    end

    @roles.delete_if do |role|
      role = Authorization::DevelopmentSupport::AnalyzerEngine::Role.for_sym(role, engine)
      ([role] + role.ancestors).all? {|inner_role| @role_privs[inner_role.to_sym].blank? }
    end

    if options[:only_relevant_contexts]
      @contexts.delete_if do |context|
        @roles.all? {|role| !@role_privs[role] || !@role_privs[role].any? {|info| info[0] == context}}
      end
    end
    
    if options[:privilege_hierarchy]
      @context_privs.each do |context, privs|
        privs.each do |priv|
          context_lower_privs = (@privilege_hierarchy[priv] || []).
                                  select {|p,c| c.nil? or c == context}.
                                  collect {|p,c| p}
          privs.concat(context_lower_privs).uniq!
        end
      end
    end
    
    render_to_string :template => 'authorization_rules/graph.dot.erb', :layout => false
  end

  def replay_changes (engine, users, changes)
    changes.inject({}) do |memo, info|
      case info[0]
      when :add_privilege, :add_role
        Authorization::DevelopmentSupport::AnalyzerEngine.apply_change(engine, info)
      when :assign_role_to_user
        user = users.find {|u| u.login == info[2]}
        user.role_symbols << info[1] if user
      end
      (memo[info[0]] ||= Set.new) << info[1..-1]
      memo
    end
  end
  
  def dot_to_svg (dot_data)
    gv = IO.popen("#{Authorization.dot_path} -q -Tsvg", "w+")
    gv.puts dot_data
    gv.close_write
    gv.read
  rescue IOError, Errno::EPIPE => e
    raise Exception, "Error in call to graphviz: #{e}"
  end
  
  def graph_options
    {
      :effective_role_privs => !params[:effective_role_privs].blank?,
      :privilege_hierarchy => !params[:privilege_hierarchy].blank?,
      :stacked_roles => !params[:stacked_roles].blank?,
      :only_relevant_roles => !params[:only_relevant_roles].blank?,
      :filter_roles => params[:filter_roles].blank? ? nil : (params[:filter_roles].is_a?(Array) ? params[:filter_roles].map(&:to_sym) : [params[:filter_roles].to_sym]),
      :filter_contexts => params[:filter_contexts].blank? ? nil : params[:filter_contexts].to_sym,
      :highlight_privilege => params[:highlight_privilege].blank? ? nil : params[:highlight_privilege].to_sym,
      :changes => deserialize_changes(params[:changes]),
      :users => params[:user_ids] && params[:user_ids].collect {|user_id| find_user_by_id(user_id)}
    }
  end

  def deserialize_changes (changes)
    if changes
      changes.split(';').collect do |info|
        info.split(',').collect do |info_part|
          info_part[0,1] == ':' ? info_part[1..-1].to_sym : info_part
        end
      end
    end
  end

  def find_user_by_id (id)
    User.find(id)
  end
  def find_all_users
    User.all.select {|user| !user.login.blank?}
  end
end

else
class AuthorizationRulesController < ApplicationController; end
end # activate_authorization_rules_browser?