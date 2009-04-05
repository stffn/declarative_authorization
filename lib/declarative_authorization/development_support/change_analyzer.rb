require File.join(File.dirname(__FILE__), %w{development_support})

module Authorization

  module DevelopmentSupport
    # Ideas for improvement
    # * Features
    #   * Support removing privilege
    #   * UI for selecting intention, defining success tests,
    #     reviewing and choosing best option
    # * Algorithm
    #   * Consider privilege hierarchy
    #   * Consider adding privilege to existing rules
    #   * Consider adding, merging, splitting roles
    #   * AI: decision tree, heuristic; chaining changes according to a plan:
    #     * adding: adding privilege to existing rule, creating new role
    #     * removing: removing privilege, adding in different role
    # * Removing need of intention
    # * Evaluation of approaches with Analyzer algorithms
    #
    class ChangeAnalyzer < AbstractAnalyzer
      attr_reader :engine

      def initialize (engine)
        @engine = engine
      end

      def find_approaches_for (change_action, type, options, &tests)
        raise ArgumentError, "Missing options" if !options[:on] or !options[:to]

        viable_approaches = []
        approach_checker = ApproachChecker.new(self, tests)

        case [change_action, type]
        when [:add, :permission]
          roles.each do |role|
            # create a copy of engine etc.
            cloned_engine = engine.clone

            # find suitable has_permission_on block or
            # create a new one for the requested info
            cloned_engine.auth_rules << AuthorizationRule.new(role.to_sym,
              [options[:to]], [options[:on]])

            if approach_checker.check(cloned_engine)
              viable_approaches << Approach.new(self, cloned_engine, :role, role)
            end
          end
        else
          raise ArgumentError, "Unknown change action/type: #{[change_action, type].inspect}"
        end
        viable_approaches
      end

      class ApproachChecker
        def initialize (analyzer, tests)
          @analyzer, @tests = analyzer, tests
        end

        def check (engine)
          @current_engine = engine
          @ok = true
          instance_eval(&@tests)
        end

        def assert (ok)
          @ok &&= ok
        end

        def permit? (*args)
          @current_engine.permit?(*args)
        end
      end

      class Approach
        attr_reader :target_type, :target
        def initialize (analyzer, engine, target_type, target)
          @analyzer, @engine, @target_type, @target = analyzer, engine, target_type, target
        end
      end
    end
  end
end
