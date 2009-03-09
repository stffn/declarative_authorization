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

  def policy_analysis_hints (marked_up, policy_data)
    analyzer = Authorization::Analyzer.new(controller.authorization_engine)
    analyzer.analyze(policy_data)
    marked_up_by_line = marked_up.split("\n")
    reports_by_line = analyzer.reports.inject({}) do |memo, report|
      memo[report.line] ||= []
      memo[report.line] << report
      memo
    end
    reports_by_line.each do |line, reports|
      note = %Q{<span class="note" title="#{reports.first.type}: #{reports.first.message}">[i]</span>}
      marked_up_by_line[line - 1] = note + marked_up_by_line[line - 1]
    end
    marked_up_by_line * "\n"
  end
  
  def link_to_graph (title, options = {})
    type = options[:type] || ''
    link_to_function title, "$$('object')[0].data = '#{url_for :action => 'index', :format => 'svg', :type => type}'"
  end
  
  def navigation
    link_to("Rules", authorization_rules_path) << ' | ' <<
    link_to("Graphical view", graph_authorization_rules_path) << ' | ' <<
    link_to("Usages", authorization_usages_path) #<< ' | ' <<
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

  def auth_usage_info_classes (auth_info)
    classes = []
    if auth_info[:controller_permissions]
      if auth_info[:controller_permissions][0]
        classes << "catch-all" if auth_info[:controller_permissions][0].actions.include?(:all)
        classes << "default-privilege" unless auth_info[:controller_permissions][0].privilege
        classes << "default-context" unless auth_info[:controller_permissions][0].context
        classes << "no-attribute-check" unless auth_info[:controller_permissions][0].attribute_check
      end
    else
      classes << "unprotected"
    end
    classes * " "
  end

  def auth_usage_info_title (auth_info)
    titles = []
    if auth_usage_info_classes(auth_info) =~ /unprotected/
      titles << "No filter_access_to call protects this action"
    end
    if auth_usage_info_classes(auth_info) =~ /no-attribute-check/
      titles << "Action is not protected with attribute check"
    end
    if auth_usage_info_classes(auth_info) =~ /default-privilege/
      titles << "Privilege set automatically from action name by :all rule"
    end
    if auth_usage_info_classes(auth_info) =~ /default-context/
      titles << "Context set automatically from controller name by filter_access_to call without :context option"
    end
    titles * ". "
  end
end
