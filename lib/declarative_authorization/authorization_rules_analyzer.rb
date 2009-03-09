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
      #p @reports
    end

    def reports
      @reports or raise "No rules analyzed!"
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
          @in_if_attribute = true
          rules = process(exp.shift).shift
          @has_permission.last[:rules] << rules if @has_permission
          @in_if_attribute = false
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
  end
end
