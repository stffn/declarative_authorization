
module Authorization
  module DevelopmentSupport
    class AbstractAnalyzer
      attr_reader :engine

      def initialize (engine)
        @engine = engine
      end

      def roles
        AnalyzerEngine.roles(engine)
      end

      def rules
        roles.collect {|role| role.rules }.flatten
      end
    end

    # Groups utility methods and classes to better work with authorization object
    # model.
    module AnalyzerEngine

      def self.roles (engine)
        rules_by_role = engine.auth_rules.inject({}) do |memo, rule|
          memo[rule.role] ||= []
          memo[rule.role] << rule
          memo
        end
        engine.roles.collect do |role|
          Role.new(role, (rules_by_role[role] || []).
                collect {|rule| Rule.new(rule, engine)}, engine)
        end
      end

      def self.relevant_roles (engine, users)
        users.collect {|user| user.role_symbols.map {|role_sym| Role.for_sym(role_sym, engine)}}.
            flatten.uniq.collect {|role| [role] + role.ancestors}.flatten.uniq
      end

      def self.rule_for_permission (engine,  privilege, context, role)
        AnalyzerEngine.roles(engine).
              find {|cloned_role| cloned_role.to_sym == role.to_sym}.rules.find do |rule|
            rule.contexts.include?(context) and rule.privileges.include?(privilege)
          end
      end

      def self.apply_change (engine, change)
        case change[0]
        when :add_role
          role_symbol = change[1]
          if engine.roles.include?(role_symbol)
            false
          else
            engine.roles << role_symbol
            true
          end
        when :add_privilege
          privilege, context, role = change[1,3]
          if rule_for_permission(engine, privilege, context, role)
            false
          else
            engine.auth_rules << AuthorizationRule.new(role.to_sym,
                [privilege], [context])
            true
          end
        when :remove_privilege
          privilege, context, role = change[1,3]
          rule_with_priv = rule_for_permission(engine, privilege, context, role)
          if rule_with_priv
            rule_with_priv.privileges.delete(privilege)
            engine.auth_rules.delete(rule_with_priv) if rule_with_priv.privileges.empty?
            true
          else
            false
          end
        end
      end

      class Role
        @@role_objects = {}
        attr_reader :role, :rules
        def initialize (role, rules, engine)
          @role = role
          @rules = rules
          @engine = engine
        end

        def source_line
          @rules.empty? ? nil : @rules.first.source_line
        end
        def source_file
          @rules.empty? ? nil : @rules.first.source_file
        end

        def ancestors (role_symbol = nil)
          role_symbol ||= @role
          (@engine.role_hierarchy[role_symbol] || []).
              collect {|lower_priv| ancestors(lower_priv) }.flatten +
            (role_symbol == @role ? [] : [Role.for_sym(role_symbol, @engine)])
        end

        def to_sym
          @role
        end
        def self.for_sym (role_sym, engine)
          @@role_objects[[role_sym, engine]] ||= new(role_sym, nil, engine)
        end
      end

      class Rule
        @@rule_objects = {}
        delegate :source_line, :source_file, :contexts, :to => :@rule
        attr_reader :rule
        def initialize (rule, engine)
          @rule = rule
          @engine = engine
        end
        def privileges
          PrivilegesSet.new(self, @engine, @rule.privileges.collect {|privilege| Privilege.for_sym(privilege, @engine) })
        end
        def self.for_rule (rule, engine)
          @@rule_objects[[rule, engine]] ||= new(rule, engine)
        end
      end

      class Privilege
        @@privilege_objects = {}
        def initialize (privilege, engine)
          @privilege = privilege
          @engine = engine
        end

        def ancestors (priv_symbol = nil)
          priv_symbol ||= @privilege
          # context-specific?
          (@engine.rev_priv_hierarchy[[priv_symbol, nil]] || []).
              collect {|lower_priv| ancestors(lower_priv) }.flatten +
            (priv_symbol == @privilege ? [] : [Privilege.for_sym(priv_symbol, @engine)])
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
        def self.for_sym (privilege_sym, engine)
          @@privilege_objects[[privilege_sym, engine]] ||= new(privilege_sym, engine)
        end

        private
        def find_rules_for_privilege
          @engine.auth_rules.select {|rule| rule.privileges.include?(@privilege)}.
              collect {|rule| Rule.for_rule(rule, @engine)}
        end
      end

      class PrivilegesSet < Set
        def initialize (*args)
          if args.length > 2
            @rule = args.shift
            @engine = args.shift
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
          Privilege.for_sym(privilege_sym, @engine)
        end
      end
    end
  end
end