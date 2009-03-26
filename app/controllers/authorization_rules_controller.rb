if Authorization::activate_authorization_rules_browser?

require File.join(File.dirname(__FILE__), %w{.. .. lib declarative_authorization authorization_rules_analyzer})

begin
  # for nice auth_rules output:
  require "parse_tree"
  require "parse_tree_extensions"
  require "ruby2ruby"
rescue LoadError; end

class AuthorizationRulesController < ApplicationController
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

  private
  def auth_to_dot (options = {})
    options = {
      :effective_role_privs => true,
      :privilege_hierarchy => false,
      :filter_roles => nil,
      :filter_contexts => nil,
      :highlight_privilege => nil
    }.merge(options)

    @highlight_privilege = options[:highlight_privilege]
    @roles = authorization_engine.roles
    @roles = @roles.select {|r| r == options[:filter_roles] } if options[:filter_roles]
    @role_hierarchy = authorization_engine.role_hierarchy
    @privilege_hierarchy = authorization_engine.privilege_hierarchy
    
    @contexts = authorization_engine.auth_rules.
                    collect {|ar| ar.contexts.to_a}.flatten.uniq
    @contexts = @contexts.select {|c| c == options[:filter_contexts] } if options[:filter_contexts]
    @context_privs = {}
    @role_privs = {}
    authorization_engine.auth_rules.each do |auth_rule|
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
      :filter_roles => params[:filter_roles].blank? ? nil : params[:filter_roles].to_sym,
      :filter_contexts => params[:filter_contexts].blank? ? nil : params[:filter_contexts].to_sym,
      :highlight_privilege => params[:highlight_privilege].blank? ? nil : params[:highlight_privilege].to_sym
    }
  end
end

else
class AuthorizationRulesController < ApplicationController; end
end # activate_authorization_rules_browser?