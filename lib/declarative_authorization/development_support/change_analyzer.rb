require File.join(File.dirname(__FILE__), %w{development_support})

module Authorization

  module DevelopmentSupport
    # Ideas for improvement
    # * Algorithm
    #   * analyze tests for conflicts
    #     * e.g. two users have a permission through the same role,
    #       one should lose that
    #   * Consider privilege hierarchy
    #   * Consider merging, splitting roles, role hierarchies
    #   * Consider adding privilege to existing rules
    # * Features
    #   * UI for selecting intention, defining success tests,
    #     reviewing and choosing best option
    #   * Show consequences from changes:
    #     * compare graphs (new edges, removed edges)
    # * AI: decision tree, heuristic (backtracking?);
    # * Removing need of intention
    # * Evaluation of approaches with Analyzer algorithms
    # * Consider constraints
    #
    class ChangeAnalyzer < AbstractAnalyzer
      attr_reader :engine

      def initialize (engine)
        @engine = engine
      end

      def find_approaches_for (change_action, type, options, &tests)
        raise ArgumentError, "Missing options" if !options[:on] or !options[:to]

        # * strategy for removing: [remove privilege, add privilege to different role]
        @seen_states = Set.new
        # * heurisic: change of failed tests;  small number of policy items
        strategy = case [change_action, type]
                   when [:remove, :permission]
                     [:remove_role_from_user, :remove_privilege, :add_privilege,
                       :add_role, :assign_role_to_user]
                   when [:add, :permission]
                     [:add_role, :add_privilege, :assign_role_to_user]
                   else
                     raise ArgumentError, "Unknown change action/type: #{[change_action, type].inspect}"
                   end

        candidates = []
        viable_approaches = []
        approach_checker = ApproachChecker.new(self, tests)

        starting_candidate = Approach.new(self, @engine, options[:users], [])
        if starting_candidate.check(approach_checker)
          viable_approaches << starting_candidate
        else
          candidates << starting_candidate
        end

        step_count = 0
        while !candidates.empty? and step_count < 100
          next_step(viable_approaches, candidates, approach_checker, options[:to], 
              options[:on], strategy)
          step_count += 1
        end
        viable_approaches.sort!
      end

      class ApproachChecker
        attr_reader :failed_test_count, :users

        def initialize (analyzer, tests)
          @analyzer, @tests = analyzer, tests
        end

        def check (engine, users)
          @current_engine = engine
          @failed_test_count = 0
          @users = users
          @ok = true
          instance_eval(&@tests)
          @ok
        end

        def assert (ok)
          @failed_test_count += 1 unless ok
          @ok &&= ok
        end

        def permit? (*args)
          @current_engine.permit?(*args)
        end
      end

      class Approach
        attr_reader :steps, :engine, :users
        def initialize (analyzer, engine, users, steps)
          @analyzer, @engine, @users, @steps = analyzer, engine, users, steps
        end

        def check (approach_checker)
          res = approach_checker.check(@engine, @users)
          @failed_test_count = approach_checker.failed_test_count
          res
        end

        def clone_for_step (*step_params)
          self.class.new(@analyzer, @engine.clone, @users.clone, @steps + [step_params])
        end

        def changes
          @steps.select {|step| step.length > 1}
        end

        def state_hash
          @engine.auth_rules.inject(0) do |memo, rule|
            memo + rule.privileges.hash + rule.contexts.hash +
                rule.attributes.hash + rule.role.hash
          end +
              @users.inject(0) {|memo, user| memo + user.role_symbols.hash } +
              @engine.privileges.hash + @engine.privilege_hierarchy.hash +
              @engine.roles.hash + @engine.role_hierarchy.hash
        end

        def sort_value
          (changes.length + 1) * (@failed_test_count.to_i + 1)
        end

        def inspect
          "Approach (#{state_hash}): Roles: #{@analyzer.roles(@engine).map(&:to_sym).inspect}; " +
              "Users: #{@users.map(&:role_symbols).inspect}"
        end

        def <=> (other)
          sort_value <=> other.sort_value
        end
      end

      protected
      def next_step (viable_approaches, candidates, approach_checker,
            privilege, context, strategy)
        candidate = candidates.shift
        next_in_strategy = strategy[candidate.steps.length % strategy.length]

        #if @seen_states.include?([candidate.state_hash, next_in_strategy])
        #  puts "SKIPPING #{next_in_strategy}; #{candidate.inspect}"
        #end
        return if @seen_states.include?([candidate.state_hash, next_in_strategy])
        @seen_states << [candidate.state_hash, next_in_strategy]
        candidate.steps << [next_in_strategy]
        candidates << candidate

        new_approaches = []

        #puts "#{next_in_strategy} on #{candidate.inspect}"
        case next_in_strategy
        when :add_role
          # ensure non-existent name
          role_symbol = :new_role_for_change_analyzer
          unless candidate.engine.roles.include?(role_symbol)
            approach = candidate.clone_for_step(:add_role, role_symbol)
            approach.engine.roles << role_symbol
            new_approaches << approach
          end
        when :assign_role_to_user
          candidate.users.each do |user|
            roles(candidate.engine).each do |role|
              next if user.role_symbols.include?(role.to_sym)
              approach = candidate.clone_for_step(:assign_role_to_user, role, user)
              # beware of shallow copies!
              cloned_user = user.clone
              approach.users[approach.users.index(user)] = cloned_user
              # possible on real user objects?
              cloned_user.role_symbols << role.to_sym
              new_approaches << approach
            end
          end
        when :remove_role_from_user
          candidate.users.each do |user|
            user.role_symbols.each do |role_sym|
              approach = candidate.clone_for_step(:remove_role_from_user, role_sym, user)
              # beware of shallow copies!
              cloned_user = user.clone
              approach.users[approach.users.index(user)] = cloned_user
              # possible on real user objects?
              cloned_user.role_symbols.delete(role_sym)
              new_approaches << approach
            end
          end
        when :add_privilege
          roles(candidate.engine).each do |role|
            approach = candidate.clone_for_step(:add_privilege, privilege, context, role)
            approach.engine.auth_rules << AuthorizationRule.new(role.to_sym,
                [privilege], [context])
            new_approaches << approach
          end
        when :remove_privilege
          roles(candidate.engine).each do |role|
            approach = candidate.clone_for_step(:remove_privilege, privilege, context, role)
            rule_with_priv = roles(approach.engine).
                find {|cloned_role| cloned_role.to_sym == role.to_sym}.
                rules.find do |rule|
              rule.contexts.include?(context) and rule.privileges.include?(privilege)
            end
            if rule_with_priv
              rule_with_priv.privileges.delete(privilege)
              approach.engine.auth_rules.delete(rule_with_priv) if rule_with_priv.privileges.empty?
              new_approaches << approach
            end
          end
        else
          raise "Unknown next strategy step #{next_in_strategy}"
        end

        new_approaches.each do |new_approach|
          if new_approach.check(approach_checker)
            viable_approaches << new_approach unless viable_approaches.find {|v_a| v_a.state_hash == new_approach.state_hash}
          else
            candidates << new_approach
          end
        end

        candidates.sort!
        #p candidates.map(&:sort_value)
      end
    end
  end
end
