require File.join(File.dirname(__FILE__), %w{development_support})

module Authorization

  module DevelopmentSupport
    # Ideas for improvement
    # * Algorithm
    #   * Objective function:
    #     * affected user count,
    #     * as specific as possible (roles, privileges)
    #     * as little changes as necessary
    #   * Modify role, privilege hierarchy
    #   * Merge, split roles
    #   * Add privilege to existing rules
    # * Features
    #   * Improve review facts: impact, affected users count
    #   * group similar candidates: only show abstract methods?
    #   * restructure GUI layout: more room for analyzing suggestions
    #   * changelog, previous tests, etc.
    #   * multiple permissions in tests
    # * Evaluation of approaches with Analyzer algorithms
    # * Authorization constraints
    #
    # Algorithm
    # * for each candidate
    #   * abstract actions: solving first failing test (remove privilege from role)
    #   * for each abstract action
    #     * specific actions: concrete steps (remove privilege from specific role)
    #     * for each specific action
    #       * next if reversal action of previous step
    #       * apply specific action on candidate
    #       * save as solution if no failing tests on changed_candidate
    #       * else: queue as candidate
    # * equivalent states
    #
    # NOTE:
    # * user.clone needs to clone role_symbols
    # * user.role_symbols needs to respond to <<
    # * user.login is needed
    #
    class ChangeSupporter < AbstractAnalyzer

      # Returns a list of possible approaches for changes to the current
      # authorization rules that achieve a given goal.  The goal is given as
      # permission tests in the block.  The instance method +users+ is available
      # when the block is executed to refer to the then-current users, whose
      # roles might have changed as one suggestion.
      def find_approaches_for (options, &tests)
        @prohibited_actions = (options[:prohibited_actions] || []).to_set

        @approaches_by_actions = {}

        candidates = []
        suggestions = []
        approach_checker = ApproachChecker.new(self, tests)

        starting_candidate = Approach.new(@engine, options[:users], [])
        if starting_candidate.check(approach_checker)
          suggestions << starting_candidate
        else
          candidates << starting_candidate
        end

        checked_candidates = 0
        while !candidates.empty? and checked_candidates < 200
          checked_candidates += next_step(suggestions, candidates, approach_checker)
        end

        # remove subsets
        suggestions.sort!
      end

      # Returns an array of GroupedApproaches for the given array of approaches.
      # Only groups directly adjacent approaches
      def group_approaches (approaches)
        approaches.each_with_object([]) do |approach, grouped|
          if grouped.last and grouped.last.approach.similar_to(approach)
            grouped.last.similar_approaches << approach
          else
            grouped << GroupedApproach.new(approach)
          end
        end
      end

      class GroupedApproach
        attr_accessor :approach, :similar_approaches
        def initialize (approach)
          @approach = approach
          @similar_approaches = []
        end
      end

      class ApproachChecker
        attr_reader :users, :failed_tests

        def initialize (analyzer, tests)
          @analyzer, @tests = analyzer, tests
        end

        def check (engine, users)
          @current_engine = engine
          @failed_tests = []
          @current_test_args = nil
          @current_permit_result = nil
          @users = users
          @ok = true
          instance_eval(&@tests)
          @ok
        end

        def assert (ok)
          @failed_tests << Test.new(*([!@current_permit_result] + @current_test_args)) unless ok
          @ok &&= ok
        end

        def permit? (*args)
          @current_test_args = args
          @current_permit_result = @current_engine.permit?(
              *(args[0...-1] + [args.last.merge(:skip_attribute_test => true)]))
        end
      end

      class Test
        attr_reader :positive, :privilege, :context, :user
        def initialize (positive, privilege, options = {})
          @positive, @privilege = positive, privilege
          @context = options[:context]
          @user = options[:user]
        end
      end

      class Approach
        attr_reader :steps, :engine, :users, :failed_tests
        def initialize (engine, users, steps)
          @engine, @users, @steps = engine, users, steps
        end

        def check (approach_checker)
          res = approach_checker.check(@engine, @users)
          @failed_tests = approach_checker.failed_tests
          #puts "CHECKING #{inspect} (#{res}, #{sort_value})"
          res
        end

        def affected_users (original_engine, original_users, privilege, context)
          (0...@users.length).select do |i|
            original_engine.permit?(privilege, :context => context,
              :skip_attribute_test => true, :user => original_users[i]) !=
                @engine.permit?(privilege, :context => context,
                  :skip_attribute_test => true, :user => @users[i])
          end.collect {|i| original_users[i]}
        end

        def initialize_copy (other)
          @engine = @engine.clone
          @users = @users.clone
          @steps = @steps.clone
        end

        def changes
          @steps
        end

        def abstract_actions
          if failed_tests.first.positive
            [
              AssignPrivilegeToRoleAction,
              AssignRoleToUserAction,
              CreateAndAssignRoleToUserAction,
              AddPrivilegeAndAssignRoleToUserAction
            ]
          else
            [
              RemovePrivilegeFromRoleAction,
              RemoveRoleFromUserAction
            ]
          end
        end

        def reverse_of_previous? (specific_action)
          changes.any? {|step| step.reverse?(specific_action)}
        end

        def apply (action)
          ok = action.apply(self)
          @steps << action if ok
          ok
        end

        def subset? (other_approach)
          other_approach.changes.length >= changes.length &&
              changes.all? {|step| other_approach.changes.any? {|step_2| step_2.eql?(step)} }
        end

        def state_hash
          @state_hash ||= @engine.auth_rules.inject(0) do |memo, rule|
              memo + rule.privileges.hash + rule.contexts.hash +
                  rule.attributes.hash + rule.role.hash
            end +
              @users.inject(0) {|memo, user| memo + user.role_symbols.hash } +
              @engine.privileges.hash + @engine.privilege_hierarchy.hash +
              @engine.roles.hash + @engine.role_hierarchy.hash
        end

        def sort_value
          weight + @failed_tests.length
        end

        def weight
          changes.sum(&:weight)
        end

        def similar_to (other)
          other.weight == weight and
              other.changes.map {|change| change.class.name}.sort ==
                changes.map {|change| change.class.name}.sort
        end

        def inspect
          "Approach: Steps: #{changes.map(&:inspect) * ', '}"# +
             # "\n  Roles: #{AnalyzerEngine.roles(@engine).map(&:to_sym).inspect}; " +
             # "\n  Users: #{@users.map(&:role_symbols).inspect}"
        end

        def <=> (other)
          sort_value <=> other.sort_value
        end
      end

      class AbstractAction
        def weight
          1
        end

        # returns a list of instances of the action that may be applied
        def self.specific_actions (candidate)
          raise NotImplementedError, "Not yet?"
        end

        # applies the specific action on the given candidate
        def apply (candidate)
          raise NotImplementedError, "Not yet?"
        end

        def eql? (other)
          other.class == self.class and hash == other.hash
        end

        def hash
          @hash ||= to_a.hash
        end

        def reverse? (other)
          false
        end

        def inspect
          "#{self.class.name.demodulize} #{hash} #{to_a.hash} (#{to_a[1..-1].collect {|info| self.class.readable_info(info)} * ','})"
        end

        def to_a
          [:abstract]
        end

        def resembles? (spec)
          min_length = [spec.length, to_a.length].min
          to_a[0,min_length] == spec[0,min_length]
        end

        def resembles_any? (specs)
          specs.any? {|spec| resembles?(spec) }
        end

        def self.readable_info (info)
          if info.respond_to?(:to_sym)
            info.to_sym.inspect
          else
            info.inspect
          end
        end
      end

      class AbstractCompoundAction < AbstractAction
        def weight
          @actions.sum(&:weight) + 1
        end

        def apply (candidate)
          @actions.all? {|action| action.apply(candidate)}
        end

        def reverse? (other)
          @actions.any? {|action| action.reverse?(other)}
        end

        def to_a
          @actions.inject([]) {|memo, action| memo += action.to_a.first.is_a?(Enumerable) ? action.to_a : [action.to_a]; memo }
        end

        def hash
          @hash ||= @actions.inject(0) {|memo, action| memo += action.hash }
        end

        def resembles? (spec)
          @actions.any? {|action| action.resembles?(spec) } or
            to_a.any? do |array|
              min_length = [spec.length, array.length].min
              array[0,min_length] == spec[0,min_length]
            end
        end
      end

      class AssignPrivilegeToRoleAction < AbstractAction
        def self.specific_actions (candidate)
          privilege = AnalyzerEngine::Privilege.for_sym(
              candidate.failed_tests.first.privilege, candidate.engine)
          context = candidate.failed_tests.first.context
          user = candidate.failed_tests.first.user
          ([privilege] + privilege.ancestors).collect do |ancestor_privilege|
            user.role_symbols.collect {|role_sym| AnalyzerEngine::Role.for_sym(role_sym, candidate.engine) }.
                collect {|role| [role] + role.ancestors}.flatten.uniq.collect do |role|
              # apply checks later if privilege is already present in that role
              new(ancestor_privilege.to_sym, context, role.to_sym)
            end
          end.flatten
        end

        attr_reader :privilege, :context, :role
        def initialize (privilege_sym, context, role_sym)
          @privilege, @context, @role = privilege_sym, context, role_sym
        end

        def apply (candidate)
          AnalyzerEngine.apply_change(candidate.engine, to_a)
        end

        def reverse? (other)
          other.is_a?(RemovePrivilegeFromRoleAction) and
              other.privilege == @privilege and
              other.context == @context and
              other.role == @role
        end

        def to_a
          [:add_privilege, @privilege, @context, @role]
        end
      end

      class AssignRoleToUserAction < AbstractAction
        def self.specific_actions (candidate)
          privilege = candidate.failed_tests.first.privilege
          context = candidate.failed_tests.first.context
          user = candidate.failed_tests.first.user
          AnalyzerEngine::Role.all_for_privilege(privilege, context, candidate.engine).collect do |role|
            new(user, role.to_sym)
          end
        end

        attr_reader :user, :role
        def initialize (user, role_sym)
          @user, @role = user, role_sym
        end

        def apply (candidate)
          if candidate.engine.roles_with_hierarchy_for(@user).include?(@role)
            false
          else
            # beware of shallow copies!
            cloned_user = @user.clone
            user_index = candidate.users.index(@user)
            raise "Cannot find #{@user.inspect} in users array" unless user_index
            candidate.users[user_index] = cloned_user
            # possible on real user objects?
            cloned_user.role_symbols << @role
            raise "User#role_symbols immutable or user only shallowly cloned!" if cloned_user.role_symbols == @user.role_symbols
            true
          end
        end

        def hash
          to_a[0,2].hash + @user.login.hash
        end

        def reverse? (other)
          other.is_a?(RemoveRoleFromUserAction) and
              other.user.login == @user.login and
              other.role == @role
        end

        def resembles? (spec)
          super(spec[0,2]) and (spec.length == 2 or spec[2] == @user.login)
        end

        def to_a
          [:assign_role_to_user, @role, @user]
        end
      end

      class CreateAndAssignRoleToUserAction < AbstractCompoundAction
        def self.specific_actions (candidate)
          privilege = AnalyzerEngine::Privilege.for_sym(
              candidate.failed_tests.first.privilege, candidate.engine)
          context = candidate.failed_tests.first.context
          user = candidate.failed_tests.first.user
          role = AnalyzerEngine::Role.for_sym(:change_supporter_new_role, candidate.engine)
          ([privilege] + privilege.ancestors).collect do |ancestor_privilege|
            new(user, ancestor_privilege.to_sym, context, role.to_sym)
          end
        end

        attr_reader :user, :privilege, :context, :role
        def initialize (user, privilege_sym, context_sym, role_sym)
          @user, @privilege, @context, @role = user, privilege_sym, context_sym, role_sym
          @actions = [AddPrivilegeAndAssignRoleToUserAction.new(@user, @privilege, @context, role_sym)]
        end

        def apply (candidate)
          if AnalyzerEngine.apply_change(candidate.engine, [:add_role, @role])
            super(candidate)
          else
            false
          end
        end

        def hash
          to_a[0].hash + super
        end

        def to_a
          [[:add_role, @role]] + super
        end
      end

      class AddPrivilegeAndAssignRoleToUserAction < AbstractCompoundAction
        def self.specific_actions (candidate)
          privilege = AnalyzerEngine::Privilege.for_sym(
              candidate.failed_tests.first.privilege, candidate.engine)
          context = candidate.failed_tests.first.context
          user = candidate.failed_tests.first.user
          ([privilege] + privilege.ancestors).collect do |ancestor_privilege|
            AnalyzerEngine::Role.all(candidate.engine).collect do |role|
              new(user, ancestor_privilege.to_sym, context, role.to_sym)
            end
          end.flatten
        end

        attr_reader :user, :privilege, :context, :role
        def initialize (user, privilege_sym, context, role_sym)
          @user, @privilege, @context, @role = user, privilege_sym, context, role_sym
          @actions = [
            AssignRoleToUserAction.new(@user, @role),
            AssignPrivilegeToRoleAction.new(@privilege, @context, @role)
          ]
        end
      end

      class RemovePrivilegeFromRoleAction < AbstractAction
        def self.specific_actions (candidate)
          privilege = AnalyzerEngine::Privilege.for_sym(
              candidate.failed_tests.first.privilege, candidate.engine)
          context = candidate.failed_tests.first.context
          user = candidate.failed_tests.first.user
          ([privilege] + privilege.ancestors).collect do |ancestor_privilege|
            user.role_symbols.collect {|role_sym| AnalyzerEngine::Role.for_sym(role_sym, candidate.engine) }.
                collect {|role| [role] + role.ancestors}.flatten.uniq.collect do |role|
              new(ancestor_privilege.to_sym, context, role.to_sym)
            end
          end.flatten
        end

        attr_reader :privilege, :context, :role
        def initialize (privilege_sym, context, role_sym)
          @privilege, @context, @role = privilege_sym, context, role_sym
        end

        def apply (candidate)
          AnalyzerEngine.apply_change(candidate.engine, to_a)
        end
        
        def reverse? (other)
          (other.is_a?(AssignPrivilegeToRoleAction) or
              other.is_a?(AbstractCompoundAction)) and
                other.reverse?(self)
        end

        def to_a
          [:remove_privilege, @privilege, @context, @role]
        end
      end

      class RemoveRoleFromUserAction < AbstractAction
        def self.specific_actions (candidate)
          privilege = candidate.failed_tests.first.privilege
          context = candidate.failed_tests.first.context
          user = candidate.failed_tests.first.user
          roles_for_privilege = AnalyzerEngine::Role.all_for_privilege(privilege, context, candidate.engine).map(&:to_sym)
          user.role_symbols.collect {|role_sym| AnalyzerEngine::Role.for_sym(role_sym, candidate.engine)}.
              select {|role| roles_for_privilege.include?(role.to_sym)}.
              collect do |role|
            new(user, role.to_sym)
          end
        end

        attr_reader :user, :role
        def initialize (user, role_sym)
          @user, @role = user, role_sym
        end

        def apply (candidate)
          # beware of shallow copies!
          cloned_user = @user.clone
          user_index = candidate.users.index(@user)
          raise "Cannot find #{@user.inspect} in users array" unless user_index
          candidate.users[user_index] = cloned_user
          cloned_user.role_symbols.delete(@role)
          raise "User#role_symbols immutable or user only shallowly cloned!" if cloned_user.role_symbols == @user.role_symbols
          true
        end

        def hash
          to_a[0,2].hash + @user.login.hash
        end

        def reverse? (other)
          (other.is_a?(AssignRoleToUserAction) or
              other.is_a?(AbstractCompoundAction)) and
                other.reverse?(self)
        end

        def resembles? (spec)
          super(spec[0,2]) and (spec.length == 2 or spec[2] == @user.login)
        end

        def to_a
          [:remove_role_from_user, @role, @user]
        end
      end

      protected
      def next_step (viable_approaches, candidates, approach_checker)
        candidate = candidates.shift

        child_candidates = generate_child_candidates(candidate)
        check_child_candidates!(approach_checker, viable_approaches, candidates, child_candidates)

        candidates.sort!
        child_candidates.length
      end

      def generate_child_candidates (candidate)
        child_candidates = []
        abstract_actions = candidate.abstract_actions
        abstract_actions.each do |abstract_action|
          abstract_action.specific_actions(candidate).each do |specific_action|
            child_candidate = candidate.dup
            if !specific_action.resembles_any?(@prohibited_actions) and
                  !child_candidate.reverse_of_previous?(specific_action) and
                  child_candidate.apply(specific_action)
              child_candidates << child_candidate
            end
          end
        end
        child_candidates
      end

      def check_child_candidates! (approach_checker, viable_approaches, candidates, child_candidates)
        child_candidates.each do |child_candidate|
          if child_candidate.check(approach_checker)
            unless superset_of_existing?(child_candidate)
              remove_supersets!(viable_approaches, child_candidate)
              viable_approaches << child_candidate
              add_to_approaches_by_action!(child_candidate)
            end
          else
            candidates << child_candidate
          end
          child_candidate.freeze
        end
      end

      def superset_of_existing? (candidate)
        candidate.changes.any? do |action|
          (@approaches_by_actions[action] ||= []).any? {|approach| approach.subset?(candidate)}
        end
      end

      def remove_supersets! (existing, candidate)
        candidate.changes.inject([]) do |memo, action|
          memo += (@approaches_by_actions[action] ||= []).select do |approach|
            candidate.subset?(approach)
          end
        end.uniq.each do |approach|
          existing.delete(approach)
          remove_from_approaches_by_action!(approach)
        end
      end

      def add_to_approaches_by_action! (candidate)
        candidate.changes.each do |action|
          (@approaches_by_actions[action] ||= []) << candidate
        end
      end

      def remove_from_approaches_by_action! (candidate)
        candidate.changes.each do |action|
          (@approaches_by_actions[action] ||= []).delete(candidate)
        end
      end

      def relevant_roles (approach)
        self.class.relevant_roles(approach)
      end
      def self.relevant_roles (approach)
        (AnalyzerEngine.relevant_roles(approach.engine, approach.users) +
            (approach.engine.roles.include?(:new_role_for_change_analyzer) ?
               [AnalyzerEngine::Role.for_sym(:new_role_for_change_analyzer, approach.engine)] : [])).uniq
      end
    end
  end
end
