
module Authorization
  module DevelopmentSupport
    class AbstractAnalyzer
      attr_reader :engine

      def initialize (engine)
        @engine = engine
      end

      def roles (specific_engine = nil)
        specific_engine ||= engine
        rules_by_role = specific_engine.auth_rules.inject({}) do |memo, rule|
          memo[rule.role] ||= []
          memo[rule.role] << rule
          memo
        end
        specific_engine.roles.collect do |role|
          Role.new(role, (rules_by_role[role] || []).
                collect {|rule| Rule.new(rule, self)})
        end
      end

      def rules
        roles.collect {|role| role.rules }.flatten
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

        def to_sym
          @role
        end
      end

      class Rule
        @@rule_objects = {}
        delegate :source_line, :source_file, :contexts, :to => :@rule
        attr_reader :rule
        def initialize (rule, analyzer)
          @rule = rule
          @analyzer = analyzer
        end
        def privileges
          PrivilegesSet.new(self, @analyzer, @rule.privileges.collect {|privilege| Privilege.for_sym(privilege, @analyzer) })
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
        def initialize (*args)
          if args.length > 2
            @rule = args.shift
            @analyzer = args.shift
          end
          super(*args)
        end
        def include? (privilege)
          if privilege.is_a?(Symbol)
            super(privilege_from_symbol(privilege))
          else
            super
          end
        end
        def delete (privilege)
          @rule.rule.privileges.delete(privilege.to_sym)
          if privilege.is_a?(Symbol)
            super(privilege_from_symbol(privilege))
          else
            super
          end
        end

        def intersects? (privileges)
          intersection(privileges).length > 0
        end

        private
        def privilege_from_symbol (privilege_sym)
          Privilege.for_sym(privilege_sym, @analyzer)
        end
      end
    end
  end
end