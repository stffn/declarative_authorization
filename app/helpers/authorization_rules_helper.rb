module AuthorizationRulesHelper
  def syntax_highlight (rules)
    regexps = {
      :constant => [/(:)(\w+)/], 
      :proc => ['role', 'authorization', 'privileges'],
      :statement => ['has_permission_on', 'if_attribute', 'if_permitted_to', 'includes', 'privilege', 'to'],
      :operator => ['is', 'contains', 'is_in', 'is_not', 'is_not_in', 'intersects'],
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
    analyzer = Authorization::DevelopmentSupport::Analyzer.new(controller.authorization_engine)
    analyzer.analyze(policy_data)
    marked_up_by_line = marked_up.split("\n")
    reports_by_line = analyzer.reports.inject({}) do |memo, report|
      memo[report.line || 1] ||= []
      memo[report.line || 1] << report
      memo
    end
    reports_by_line.each do |line, reports|
      text = reports.collect {|report| "#{report.type}: #{report.message}"} * " "
      note = %Q{<span class="note" title="#{h text}">[i]</span>}
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
    link_to("Change Support", change_authorization_rules_path) << ' | ' <<
    link_to("Graphical view", graph_authorization_rules_path) << ' | ' <<
    link_to("Usages", authorization_usages_path) #<< ' | ' <<
  #  'Edit | ' <<
  #  link_to("XACML export", :action => 'index', :format => 'xacml')
  end
  
  def role_color (role, fill = false)
    if @has_changes
      if has_changed(:add_role, role)
        fill ? '#ddffdd' : '#000000'
      elsif has_changed(:remove_role, role)
        fill ? '#ffdddd' : '#000000'
      else
        fill ? '#ddddff' : '#000000'
      end
    else
      fill_colors = %w{#ffdddd #ddffdd #ddddff #ffffdd #ffddff #ddffff}
      colors = %w{#dd0000 #00dd00 #0000dd #dddd00 #dd00dd #00dddd}
      @@role_colors ||= {}
      @@role_colors[role] ||= begin
        idx = @@role_colors.length % colors.length
        [colors[idx], fill_colors[idx]]
      end
      @@role_colors[role][fill ? 1 : 0]
    end
  end
  
  def role_fill_color (role)
    role_color(role, true)
  end

  def privilege_color (privilege, context, role)
    has_changed(:add_privilege, privilege, context, role) ? '#00dd00' :
        (has_changed(:remove_privilege, privilege, context, role) ? '#dd0000' :
          role_color(role))
  end

  def human_privilege (privilege)
    begin
      I18n.t(privilege, :scope => [:declarative_authorization, :privilege], :raise => true)
    rescue
      privilege.to_s
    end
  end

  def human_context (context)
    begin
      context.to_s.classify.constantize.human_name
    rescue
      context.to_s
    end
  end

  def human_privilege_context (privilege, context)
    human = [human_privilege(privilege), human_context(context)]
    begin
      unless I18n.t(:verb_in_front_of_object, :scope => :declarative_authorization, :raise => true)
        human.reverse!
      end
    rescue
    end
    human * " "
  end

  def human_role (role)
    Authorization::Engine.instance.title_for(role) or role.to_s
  end

  def describe_step (step, options = {})
    options = {:with_removal => false}.merge(options)

    case step[0]
    when :add_privilege
      dont_assign = prohibit_link(step[0,3],
          "Add privilege <strong>#{h human_privilege_context(step[1], step[2])}</strong> to any role",
          "Don't suggest adding #{h human_privilege_context(step[1], step[2])}.", options)
      "Add privilege <strong>#{h human_privilege_context(step[1], step[2])}</strong>#{dont_assign} to role <strong>#{h human_role(step[3].to_sym)}</strong>"
    when :remove_privilege
      dont_remove = prohibit_link(step[0,3], 
          "Remove privilege <strong>#{h human_privilege_context(step[1], step[2])}</strong> from any role",
          "Don't suggest removing #{h human_privilege_context(step[1], step[2])}.", options)
      "Remove privilege <strong>#{h human_privilege_context(step[1], step[2])}</strong>#{dont_remove} from role <strong>#{h human_role(step[3].to_sym)}</strong>"
    when :add_role
      "New role <strong>#{h human_role(step[1].to_sym)}</strong>"
    when :assign_role_to_user
      dont_assign = prohibit_link(step[0,2],
          "Assign role <strong>#{h human_role(step[1].to_sym)}</strong> to any user",
          "Don't suggest assigning #{h human_role(step[1].to_sym)}.", options)
      "Assign role <strong>#{h human_role(step[1].to_sym)}</strong>#{dont_assign} to <strong>#{h readable_step_info(step[2])}</strong>"
    when :remove_role_from_user
      dont_remove = prohibit_link(step[0,2],
          "Remove role <strong>#{h human_role(step[1].to_sym)}</strong> from any user",
          "Don't suggest removing #{h human_role(step[1].to_sym)}.", options)
      "Remove role <strong>#{h human_role(step[1].to_sym)}</strong>#{dont_remove} from <strong>#{h readable_step_info(step[2])}</strong>"
    else
      step.collect {|info| readable_step_info(info) }.map {|str| h str } * ', '
    end + prohibit_link(step, options[:with_removal] ? "#{escape_javascript(describe_step(step))}" : '',
                        "Don't suggest this action.", options)
  end

  def prohibit_link (step, text, title, options)
    options[:with_removal] ?
          link_to_function("[x]", "prohibit_action('#{serialize_action(step)}', '#{text}')",
                    :class => 'prohibit', :title => title) :
          ''
  end
  
  def readable_step_info (info)
    case info
    when Symbol   then info.inspect
    when User     then info.login
    else               info.to_sym.inspect
    end
  end

  def serialize_changes (approach)
    changes = approach.changes.collect {|step| step.to_a.first.is_a?(Enumerable) ? step.to_a : [step.to_a]}
    changes.collect {|multi_step| multi_step.collect {|step| serialize_action(step) }}.flatten * ';'
  end

  def serialize_action (step)
    step.collect {|info| readable_step_info(info) } * ','
  end

  def serialize_relevant_roles (approach)
    {:filter_roles => (Authorization::DevelopmentSupport::AnalyzerEngine.relevant_roles(approach.engine, approach.users).
        map(&:to_sym) + [:new_role_for_change_analyzer]).uniq}.to_param
  end

  def has_changed (*args)
    @changes && @changes[args[0]] && @changes[args[0]].include?(args[1..-1])
  end

  def affected_users_count (approach)
    @affected_users[approach]
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
