module AuthorizationRulesHelper
  def syntax_highlight (rules)
    regexps = {
      :constant => [/(:)(\w+)/], 
      :proc => ['role', 'authorization', 'privileges'],
      :statement => ['has_permission_on', 'if_attribute', 'includes', 'privilege', 'to'],
      :operator => ['is', 'contains'],
      :special => ['user', 'true', 'false'],
      :preproc => ['do', 'end', /()(=&gt;)/, /()(\{)/, /()(\})/, /()(\[)/, /()(\])/],
      :comment => [/()(#.*$)/]#,
      #:privilege => [:read],
      #:context => [:conferences]
    }
    regexps.each do |name, res|
      res.each do |re|
        rules.gsub!(
          re.is_a?(String) ? Regexp.new("(^|[^:])\\b(#{Regexp.escape(re)})\\b") :
             (re.is_a?(Symbol) ? Regexp.new("()(:#{Regexp.escape(re.to_s)})\\b") : re), 
          "\\1<span class=\"#{name}\">\\2</span>")
      end
    end
    rules
  end
  
  def link_to_graph (title, options = {})
    type = options[:type] || ''
    link_to_function title, "$$('object')[0].data = '#{url_for :action => 'index', :format => 'svg', :type => type}'"
  end
  
  def navigation
    link_to("Rules", authorization_rules_path) << ' | ' <<
    link_to("Graphical view", graph_authorization_rules_path) #<< ' | ' <<
  #  'Edit | ' <<
  #  link_to("XACML export", :action => 'index', :format => 'xacml')
  end
  
  def role_color (role, fill = false)
    fill_colors = %w{#ffdddd #ddffdd #ddddff #ffffdd #ffddff #ddffff}
    colors = %w{#dd0000 #00dd00 #0000dd #dddd00 #dd00dd #00dddd}
    @@role_colors ||= {}
    @@role_colors[role] ||= begin
      idx = @@role_colors.length % colors.length
      [colors[idx], fill_colors[idx]]
    end
    @@role_colors[role][fill ? 1 : 0]
  end
  
  def role_fill_color (role)
    role_color(role, true)
  end
end
