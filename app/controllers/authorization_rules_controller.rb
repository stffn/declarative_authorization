if Authorization::activate_authorization_rules_browser?

require File.join(File.dirname(__FILE__), %w{.. .. lib declarative_authorization development_support analyzer})
require File.join(File.dirname(__FILE__), %w{.. .. lib declarative_authorization development_support change_analyzer})

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
    # TODO not generic enough
    @users = User.all
    @users.sort! {|a, b| a.login <=> b.login }
  end

  def suggest_change
    users_permission = params[:user].inject({}) do |memo, (user_id, data)|
      if data[:permission] != "undetermined"
        begin
          memo[User.find(user_id)] = (data[:permission] == 'yes')
        rescue ActiveRecord::NotFound
        end
      end
      memo
    end

    users_keys = users_permission.keys
    analyzer = Authorization::DevelopmentSupport::ChangeAnalyzer.new(authorization_engine)
    
    privilege = params[:privilege].to_sym
    context = params[:context].to_sym
    @context = context
    @approaches = analyzer.find_approaches_for(params[:goal].to_sym,
        :permission, :on => context, :to => privilege, :users => users_keys) do
      users.each_with_index do |user, idx|
        args = [privilege, {:context => context, :user => user}]
        assert(users_permission[users_keys[idx]] ? permit?(*args) : !permit?(*args))
      end
    end

    respond_to do |format|
      format.js do
        render :partial => 'suggestion'
      end
    end
  end

  private
  def auth_to_dot (options = {})
    options = {
      :effective_role_privs => true,
      :privilege_hierarchy => false,
      :only_relevant_contexts => true,
      :filter_roles => nil,
      :filter_contexts => nil,
      :highlight_privilege => nil,
      :changes => nil
    }.merge(options)

    @has_changes = options[:changes] && !options[:changes].empty?
    @highlight_privilege = options[:highlight_privilege]

    engine = authorization_engine.clone

    filter_roles_flattened = nil
    if options[:filter_roles]
      filter_roles_flattened = options[:filter_roles].collect do |role_sym|
        Authorization::DevelopmentSupport::AnalyzerEngine::Role.for_sym(role_sym, engine).
            ancestors.map(&:to_sym) + [role_sym]
      end.flatten.uniq
    end

    @changes = replay_changes(engine, options[:changes]) if options[:changes]
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
        @role_privs[role] ||= []
        (@role_hierarchy[role] || []).each do |lower_role|
          @role_privs[role].concat(@role_privs[lower_role]).uniq!
        end
      end
    end

    if options[:only_relevant_contexts]
      @contexts.delete_if {|context| @roles.all? {|role| !@role_privs[role] || !@role_privs[role].any? {|info| info[0] == context}}}
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

  def replay_changes (engine, changes)
    changes.inject({}) do |memo, info|
      case info[0]
      when :add_privilege, :add_role
        Authorization::DevelopmentSupport::AnalyzerEngine.apply_change(engine, info)
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
      :filter_roles => params[:filter_roles].blank? ? nil : (params[:filter_roles].is_a?(Array) ? params[:filter_roles].map(&:to_sym) : [params[:filter_roles].to_sym]),
      :filter_contexts => params[:filter_contexts].blank? ? nil : params[:filter_contexts].to_sym,
      :highlight_privilege => params[:highlight_privilege].blank? ? nil : params[:highlight_privilege].to_sym,
      :changes => deserialize_changes(params[:changes])
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
end

else
class AuthorizationRulesController < ApplicationController; end
end # activate_authorization_rules_browser?