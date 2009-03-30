begin
  require "ruby_parser"
  #require "parse_tree"
  #require "parse_tree_extensions"
  require "sexp_processor"
rescue LoadError
  raise "Authorization::Analyzer requires ruby_parser gem"
end

module Authorization

  class Analyzer
    attr_reader :engine

    def initialize (engine)
      @engine = engine
    end

    def analyze (rules)
      sexp_array = RubyParser.new.parse(rules)
      #sexp_array = ParseTree.translate(rules)
      @reports = []
      [MergeableRulesProcessor].each do |parser|
        parser.new(self).analyze(sexp_array)
      end
      [
        RoleExplosionAnalyzer, InheritingPrivilegesAnalyzer,
        ProposedPrivilegeHierarchyAnalyzer
      ].each do |parser|
        parser.new(self).analyze
      end
    end

    def reports
      @reports or raise "No rules analyzed!"
    end

    class GeneralRulesAnalyzer
      def initialize(analyzer)
        @analyzer = analyzer
      end

      def analyze
        mark(:policy, nil) if analyze_policy
        roles.select {|role| analyze_role(role) }.
            each { |role| mark(:role, role) }
        rules.select {|rule| analyze_rule(rule) }.
            each { |rule| mark(:rule, rule) }
        privileges.select {|privilege| !!analyze_privilege(privilege) }.
            each { |privilege| mark(:privilege, privilege) }
      end

      protected
      def roles
        @analyzer.engine.auth_rules.inject({}) do |memo, rule|
          memo[rule.role] ||= []
          memo[rule.role] << rule
          memo
        end.collect {|role, rules| Role.new(role, rules.collect {|rule| Rule.new(rule, @analyzer)})}
      end

      def rules
        roles.collect {|role| role.rules }.flatten
      end

      def privileges
        @privileges ||= rules.collect {|rule| rule.privileges.to_a}.flatten.uniq
      end

      # to be implemented by specific processor
      def analyze_policy; end
      def analyze_role (a_role); end
      def analyze_rule (a_rule); end
      def analyze_privilege (a_privilege); end
      def message (object); end

      private
      def source_line (object)
        object.source_line if object.respond_to?(:source_line)
      end
      
      def source_file (object)
        object.source_file if object.respond_to?(:source_file)
      end

      def mark (type, object)
        @analyzer.reports << Report.new(report_type,
            source_file(object), source_line(object), message(object))
      end

      # analyzer class name stripped of last word
      def report_type
        (self.class.name.demodulize.underscore.split('_')[0...-1] * '_').to_sym
      end
    end

    class RoleExplosionAnalyzer < GeneralRulesAnalyzer
      SMALL_ROLE_RULES_COUNT = 3
      SMALL_ROLES_RATIO = 0.2

      def analyze_policy
        small_roles.count > 1 and small_roles.count.to_f / roles.count.to_f > SMALL_ROLES_RATIO
      end

      def message (object)
        "The ratio of small roles is quite high (> %.0f%%).  Consider refactoring." % (SMALL_ROLES_RATIO * 100)
      end

      private
      def small_roles
        roles.select {|role| role.rules.count < SMALL_ROLE_RULES_COUNT }
      end
    end

    class InheritingPrivilegesAnalyzer < GeneralRulesAnalyzer
      def analyze_rule (rule)
        rule.privileges.any? {|privilege| rule.privileges.intersects?(privilege.ancestors) }
      end

      def message (object)
        "At least one privilege inherits from another in this rule."
      end
    end

    class ProposedPrivilegeHierarchyAnalyzer < GeneralRulesAnalyzer
      # TODO respect, consider contexts
      def analyze_privilege (privilege)
        privileges.find do |other_privilege|
          other_privilege != privilege and
              other_privilege.rules.all? {|rule| rule.privileges.include?(privilege)}
        end
      end

      def message (privilege)
        other_privilege = analyze_privilege(privilege)
        "Privilege #{other_privilege.to_sym} is always used together with #{privilege.to_sym}. " +
            "Consider to include #{other_privilege.to_sym} in #{privilege.to_sym}."
      end
    end

    class GeneralAuthorizationProcessor < SexpProcessor
      def initialize(analyzer)
        super()
        self.auto_shift_type = true
        self.require_empty = false
        self.strict = false
        @analyzer = analyzer
      end

      def analyze (sexp_array)
        process(sexp_array)
        analyze_rules
      end

      def analyze_rules
        # to be implemented by specific processor
      end

      def process_iter (exp)
        s(:iter, process(exp.shift), process(exp.shift), process(exp.shift))
      end

      def process_arglist (exp)
        s(exp.collect {|inner_exp| process(inner_exp).shift})
      end

      def process_hash (exp)
        s(Hash[*exp.collect {|inner_exp| process(inner_exp).shift}])
      end

      def process_lit (exp)
        s(exp.shift)
      end
    end

    class MergeableRulesProcessor < GeneralAuthorizationProcessor
      def analyze_rules
        if @has_permission
          #p @has_permission
          permissions_by_context_and_rules = @has_permission.inject({}) do |memo, permission|
            key = [permission[:context], permission[:rules]]
            memo[key] ||= []
            memo[key] << permission
            memo
          end

          permissions_by_context_and_rules.each do |key, rules|
            if rules.length > 1
              rule_lines = rules.collect {|rule| rule[:line] }
              rules.each do |rule|
                @analyzer.reports << Report.new(:mergeable_rules, "", rule[:line],
                  "Similar rules already in line(s) " +
                      rule_lines.reject {|l| l == rule[:line] } * ", ")
              end
            end
          end
        end
      end

      def process_call (exp)
        klass = exp.shift
        name = exp.shift
        case name
        when :role
          analyze_rules
          @has_permission = []
          s(:call, klass, name)
        when :has_permission_on
          arglist_line = exp[0].line
          arglist = process(exp.shift).shift
          context = arglist.shift
          args_hash = arglist.shift
          @has_permission << {
            :context => context,
            :rules => [],
            :privilege => args_hash && args_hash[:to],
            # a hack: call exp line seems to be wrong
            :line => arglist_line
          }
          s(:call, klass, name)
        when :to
          @has_permission.last[:privilege] = process(exp.shift).shift if @has_permission
          s(:call, klass, name)
        when :if_attribute
          rules = process(exp.shift).shift
          rules.unshift :if_attribute
          @has_permission.last[:rules] << rules if @has_permission
          s(:call, klass, name)
        when :if_permitted_to
          rules = process(exp.shift).shift
          rules.unshift :if_permitted_to
          @has_permission.last[:rules] << rules if @has_permission
          s(:call, klass, name)
        else
          s(:call, klass, name, process(exp.shift))
        end
      end
    end

    class Report
      attr_reader :type, :filename, :line, :message
      def initialize (type, filename, line, msg)
        @type = type
        @filename = filename
        @line = line
        @message = msg
      end
    end

    class Role
      attr_reader :role, :rules
      def initialize (role, rules)
        @role = role
        @rules = rules
      end
      def source_line
        @rules.empty? ? nil : @rules.first.source_line
      end
      def source_file
        @rules.empty? ? nil : @rules.first.source_file
      end
    end

    class Rule
      @@rule_objects = {}
      delegate :source_line, :source_file, :to => :@rule
      def initialize (rule, analyzer)
        @rule = rule
        @analyzer = analyzer
      end
      def privileges
        PrivilegesSet.new(@rule.privileges.collect {|privilege| Privilege.for_sym(privilege, @analyzer) })
      end

      def self.for_sym (rule_sym, analyzer)
        @@rule_objects[[rule_sym, analyzer]] ||= new(rule_sym, analyzer)
      end
    end

    class Privilege
      @@privilege_objects = {}
      def initialize (privilege, analyzer)
        @privilege = privilege
        @analyzer = analyzer
      end

      def ancestors (priv_symbol = nil)
        priv_symbol ||= @privilege
        # context-specific?
        (@analyzer.engine.rev_priv_hierarchy[[priv_symbol, nil]] || []).
            collect {|lower_priv| ancestors(lower_priv) }.flatten +
          (priv_symbol == @privilege ? [] : [Privilege.for_sym(priv_symbol, @analyzer)])
      end

      def rules
        @rules ||= find_rules_for_privilege
      end
      def source_line
        rules.empty? ? nil : rules.first.source_line
      end
      def source_file
        rules.empty? ? nil : rules.first.source_file
      end

      def to_sym
        @privilege
      end
      def self.for_sym (privilege_sym, analyzer)
        @@privilege_objects[[privilege_sym, analyzer]] ||= new(privilege_sym, analyzer)
      end

      private
      def find_rules_for_privilege
        @analyzer.engine.auth_rules.select {|rule| rule.privileges.include?(@privilege)}.
            collect {|rule| Rule.for_sym(rule, @analyzer)}
      end
    end

    class PrivilegesSet < Set
      def intersects? (privileges)
        intersection(privileges).length > 0
      end
    end
  end
end
