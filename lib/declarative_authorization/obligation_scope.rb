module Authorization
  # The +ObligationScope+ class parses any number of obligations into joins and conditions.
  #
  # In +ObligationScope+ parlance, "association paths" are one-dimensional arrays in which each
  # element represents an attribute or association (or "step"), and "leads" to the next step in the
  # association path.
  #
  # Suppose we have this path defined in the context of model Foo:
  # +{ :bar => { :baz => { :foo => { :attr => is { user } } } } }+
  #
  # To parse this path, +ObligationScope+ evaluates each step in the context of the preceding step.
  # The first step is evaluated in the context of the parent scope, the second step is evaluated in
  # the context of the first, and so forth.  Every time we encounter a step representing an
  # association, we make note of the fact by storing the path (up to that point), assigning it a
  # table alias intended to match the one that will eventually be chosen by ActiveRecord when
  # executing the +find+ method on the scope.
  #
  # +@table_aliases = {
  #   [] => 'foos',
  #   [:bar] => 'bars',
  #   [:bar, :baz] => 'bazzes',
  #   [:bar, :baz, :foo] => 'foos_bazzes' # Alias avoids collisions with 'foos' (already used)
  # }+
  #
  # At the "end" of each path, we expect to find a comparison operation of some kind, generally
  # comparing an attribute of the most recent association with some other value (such as an ID,
  # constant, or array of values).  When we encounter a step representing a comparison, we make
  # note of the fact by storing the path (up to that point) and the comparison operation together.
  # (Note that individual obligations' conditions are kept separate, to allow their conditions to
  # be OR'ed together in the generated scope options.)
  #
  # +@obligation_conditions[<obligation>][[:bar, :baz, :foo]] = [
  #   [ :attr, :is, <user.id> ]
  # ]+
  #
  # TODO update doc for Relations:
  # After successfully parsing an obligation, all of the stored paths and conditions are converted
  # into scope options (stored in +proxy_options+ as +:joins+ and +:conditions+).  The resulting
  # scope may then be used to find all scoped objects for which at least one of the parsed
  # obligations is fully met.
  #
  # +@proxy_options[:joins] = { :bar => { :baz => :foo } }
  # @proxy_options[:conditions] = [ 'foos_bazzes.attr = :foos_bazzes__id_0', { :foos_bazzes__id_0 => 1 } ]+
  #
  class ObligationScope < (Rails.version < "3" ? ActiveRecord::NamedScope::Scope : ActiveRecord::Relation)
    attr_reader :finder_options

    def initialize (model, options)
      @finder_options = {}
      if Rails.version < "3"
        super(model, options)
      elsif Rails.version < "5"
        super(model, model.table_name)
      else
	      super(model, model.table_name, model.predicate_builder)
      end
    end

    def scope
      if Rails.version < "3"
        self
      elsif Rails.version < "4"
        # for Rails < 4: use scoped method
        self.klass.scoped(@finder_options.merge(readonly: false))
      else
        # TODO Refactor this.  There is certainly a better way.
        self.klass.joins(@finder_options[:joins]).
          includes(@finder_options[:include]).
          where(@finder_options[:conditions]).
          references(@finder_options[:include]).
          readonly(false)
      end
    end

    # Consumes the given obligation, converting it into scope join and condition options.
    def parse!( obligation )
      @current_obligation = obligation
      @join_table_joins = Set.new
      obligation_conditions[@current_obligation] ||= {}
      follow_path( obligation )

      rebuild_condition_options!
      rebuild_join_options!
    end

    protected

    # Parses the next step in the association path.  If it's an association, we advance down the
    # path.  Otherwise, it's an attribute, and we need to evaluate it as a comparison operation.
    def follow_path(steps, past_steps=[])
      if steps.is_a?( Hash )
        steps.each do |step, next_steps|
          path_to_this_point = [past_steps, step].flatten
          init_reflections_for past_steps
          follow_path(next_steps, path_to_this_point)
          # follow_comparison( next_steps, past_steps, step )
        end
      elsif steps.is_a?(Array) && steps.length == 2
        init_reflections_for past_steps

        if reflections_for(past_steps)
          follow_comparison(steps, past_steps, :id)
        else
          follow_comparison(steps, past_steps[0..-2], past_steps[-1])
        end
      else
        raise "invalid obligation path #{[past_steps, steps].inspect}"
      end
    end

    def top_level_model
      klass
    end

    # At the end of every association path, we expect to see a comparison of some kind; for
    # example, +:attr => [ :is, :value ]+.
    #
    # This method parses the comparison and creates an obligation condition from it.
    def follow_comparison(steps, past_steps, attribute)
      operator = steps[0]
      value = steps[1..-1]
      value = value[0] if value.length == 1

      add_obligation_condition_for(past_steps, [attribute, operator, value])
    end

    # Adds the given expression to the current obligation's indicated path's conditions.
    #
    # Condition expressions must follow the format +[ <attribute>, <operator>, <value> ]+.
    def add_obligation_condition_for(path, expression)
      (obligation_conditions[@current_obligation][path] ||= Set.new) << expression
    end

    def reflections_for(path)
      reflections[path]
    end

    # Returns the reflection corresponding to the given path.
    def init_reflections_for(path, for_join_table_only = false)
      @join_table_joins << path if for_join_table_only && !reflections_for(path)
      reflections_for(path) || map_reflection_for(path)
    end

    # Attempts to map a reflection for the given path.  Raises if already defined.
    def map_reflection_for(path)
      refls_for_path = reflections_for_path path

      return nil if refls_for_path.empty?
      reflections[path] = refls_for_path

      init_table_alias_for path  # Claim a table alias for the path.

      # Claim alias for join table
      # TODO change how this is checked
      refls_for_path.each do |reflection|
        if !Authorization.is_a_association_proxy?(reflection) && reflection.is_a?(ActiveRecord::Reflection::ThroughReflection)
          join_table_path = path[0..-2] + [reflection.options[:through]]
          init_reflections_for(join_table_path, true)
        end
      end

      refls_for_path
    end

    def reflections_for_path(path)
      return [top_level_model] if path.empty?

      refls_for = reflections_for_path path[0..-2]

      refls_for_path = refls_for.map do |refl_for|
        if polymorphic?(refl_for)
          refl_for.active_record.poly_resources
        elsif !Authorization.is_a_association_proxy?(refl_for) and refl_for.respond_to?(:klass)
          refl_for.klass
        else
          refl_for
        end
      end.flatten.uniq

      refls_for_path.map do |refl|
        refl.reflect_on_association path.last
      end.compact
    end

    # Returns the model associated with the given path.
    def models_for(path)
      reflections_for(path).map do |reflection|
        if Authorization.is_a_association_proxy?(reflection)
          if Rails.version < "3.2"
            reflection.proxy_reflection.klass
          else
            reflection.proxy_association.reflection.klass
          end
        elsif reflection.respond_to?(:klass)
          if polymorphic?(reflection)
            reflection.active_record.poly_resources
          else
            reflection.klass
          end
        else
          reflection
        end
      end.flatten.uniq
    end

    # Returns a proper table alias for the given path.  This alias may be used in SQL statements.
    def table_alias_for(path)
      table_aliases[path] || init_table_alias_for( path )
    end

    # Attempts to map a table alias for the given path.  Raises if already defined.
    def init_table_alias_for( path )
      raise "table alias for #{path.inspect} already exists" unless table_aliases[path].nil?

      table_aliases[path] = reflections_for(path).map do |ref_for|
        if polymorphic?(ref_for)
          rel_name = ref_for.active_record
          rel_name.poly_resources.map { |res| construct_table_alias res }
        else
          construct_table_alias ref_for
        end
      end.flatten.uniq
    end

    def construct_table_alias(reflection)
      table_alias = reflection.table_name
      if table_aliases.values.flatten.include?( table_alias )
        max_length = reflection.active_record.connection.table_alias_length
        # Rails seems to pluralize reflection names
        table_alias = "#{reflection.name.to_s.pluralize}_#{reflection.active_record.table_name}".to(max_length-1)
      end
      while table_aliases.values.flatten.include?( table_alias )
        if table_alias =~ /\w(_\d+?)$/
          table_index = $1.succ
          table_alias = "#{table_alias[0..-(table_index.length+1)]}_#{table_index}"
        else
          table_alias = "#{table_alias[0..(max_length-3)]}_2"
        end
      end

      table_alias
    end

    def polymorphic?(relation)
      relation.respond_to?(:options) && relation.options[:polymorphic]
    end

    # Returns a hash mapping obligations to zero or more condition path sets.
    def obligation_conditions
      @obligation_conditions ||= {}
    end

    # Returns a hash mapping paths to reflections.
    def reflections
      # lets try to get the order of joins right
      @reflections ||= ActiveSupport::OrderedHash.new
    end

    # Returns a hash mapping paths to proper table aliases to use in SQL statements.
    def table_aliases
      @table_aliases ||= {}
    end

    # Parses all of the defined obligation conditions and defines the scope's :conditions option.
    def rebuild_condition_options!
      conds = []
      binds = {}
      obligation_conditions.each_with_index do |(_, conditions), obligation_index|
        obligation_conds = []
        obligation_conds_poly = []

        conditions.each do |path, expressions|
          models = models_for path
          raise "too many models" if models.length > 1
          model = models.first

          table_alias_list = table_alias_for(path)
          parent_models = (path.length > 1 ? models_for(path[0..-2]) : [top_level_model])
          parent_is_polymorphic = parent_models.length > 1

          parent_models.each do |parent_model|

            expressions.each do |expression|
              attribute, operator, value = expression
              # prevent unnecessary joins:
              if attribute == :id and operator == :is and parent_model.columns_hash["#{path.last}_id"]
                attribute_name = :"#{path.last}_id"
                attribute_table_alias_list = table_alias_for(path[0..-2])
              else
                attribute_name = model.columns_hash["#{attribute}_id"] && :"#{attribute}_id" ||
                                 model.columns_hash[attribute.to_s]    && attribute ||
                                 model.primary_key
                attribute_table_alias_list = table_alias_list
              end

              attribute_table_alias_list.each do |attribute_table_alias|
                bindvar = "#{attribute_table_alias}__#{attribute_name}_#{obligation_index}".to_sym

                sql_attribute = "#{parent_model.connection.quote_table_name(attribute_table_alias)}." +
                    "#{parent_model.connection.quote_table_name(attribute_name)}"

                obligation_cond =
                  if value.nil? and [:is, :is_not].include?(operator)
                    "#{sql_attribute} IS #{[:contains, :is].include?(operator) ? '' : 'NOT '}NULL"
                  else
                    attribute_operator = case operator
                                         when :contains, :is             then "= :#{bindvar}"
                                         when :does_not_contain, :is_not then "<> :#{bindvar}"
                                         when :is_in, :intersects_with   then "IN (:#{bindvar})"
                                         when :is_not_in                 then "NOT IN (:#{bindvar})"
                                         when :lt                        then "< :#{bindvar}"
                                         when :lte                       then "<= :#{bindvar}"
                                         when :gt                        then "> :#{bindvar}"
                                         when :gte                       then ">= :#{bindvar}"
                                         else raise AuthorizationUsageError, "Unknown operator: #{operator}"
                                         end

                    binds[bindvar] = attribute_value(value)
                    "#{sql_attribute} #{attribute_operator}"
                  end

                if parent_is_polymorphic && attribute == :id
                  obligation_conds_poly << obligation_cond
                else
                  obligation_conds << obligation_cond
                end
              end
            end
          end
        end

        # join conditions directly connecting a parent to its polymorphic children by OR
        poly_conds_sql = obligation_conds_poly.empty? ? nil : "(#{obligation_conds_poly.uniq.join(' OR ')})"

        # remove any duplicate ordinary conditions (defined multiple times because of polymorphism)
        obligation_conds.uniq!

        obligation_conds << poly_conds_sql if poly_conds_sql
        obligation_conds << "1=1" if obligation_conds.empty?
        conds << "(#{obligation_conds.join(' AND ')})"
      end

      finder_options[:conditions] = [ conds.join( " OR " ), binds ]
    end

    def attribute_value (value)
      value_record?(value) && value.id ||
      (value_array?(value) || value_relation?(value)) && value.to_a.map( &:id ) ||
      value
    end

    def value_record?(value)
      value.class.respond_to?(:descends_from_active_record?) && value.class.descends_from_active_record?
    end

    def value_array?(value)
      value.is_a?(Array) && value[0].class.respond_to?(:descends_from_active_record?) && value[0].class.descends_from_active_record?
    end

    def value_relation?(value)
      value.is_a?(ActiveRecord::Relation)
    end

    # Parses all of the defined obligation joins and defines the scope's :joins or :includes option.
    # TODO: Support non-linear association paths.  Right now, we just break down the longest path parsed.
    def rebuild_join_options!
      joins = (finder_options[:joins] || []) + (finder_options[:includes] || [])

      polymorphic_paths = {}
      reflections.each do |path, refs|
        next if path.empty? or @join_table_joins.include?(path)

        first_ref = refs.first
        if polymorphic?(first_ref)
          # sanity check
          raise "Only one polymorphic relation is allowed at each step" if refs.length > 1

          polymorphic_paths[path] = first_ref.active_record.poly_resource_names
        end

        existing_join = joins.find do |join|
          existing_path = join_to_path(join)
          min_length = [existing_path.length, path.length].min
          existing_path.first(min_length) == path.first(min_length)
        end

        if existing_join
          if join_to_path(existing_join).length < path.length
            joins[joins.index(existing_join)] = path_to_join(path)
          end
        else
          joins << path_to_join(path)
        end
      end

      # construct normal joins replacing polymorphic references to the actual resources (of which there can be many)
      polymorphic_paths.to_a.sort_by { |p| p.first.length }.reverse.each do |ppath, resource_names|
        normalised_joins = []
        joins.each do |join|
          path = join_to_path join

          # check if ppath is a subset of path
          if ppath == path[0, ppath.length]
            resource_names.each do |resource_name|
              resource_idx = ppath.length - 1
              path[resource_idx] = resource_name
              normal_join = path_to_join path

              normalised_joins << normal_join
            end
          else
            normalised_joins << join
          end
        end

        joins = normalised_joins
      end

      conds_len = obligation_conditions.length
      if conds_len == 0
        # No obligation conditions means we don't have to mess with joins or includes at all.
      elsif conds_len == 1 && polymorphic_paths.empty?
        # joins in a scope are converted to inner joins
        finder_options[:joins] = joins
        finder_options.delete( :include )
      else
        # polymorphic paths must use left joins (include)
        # include in a scope is converted to left joins
        finder_options.delete( :joins )
        finder_options[:include] = joins
      end
    end

    def path_to_join (path)
      case path.length
      when 0 then nil
      when 1 then path[0]
      else
        hash = { path[-2] => path[-1] }
        path[0..-3].reverse.each do |elem|
          hash = { elem => hash }
        end
        hash
      end
    end

    def join_to_path (join)
      case join
      when Symbol
        [join]
      when Hash
        [join.keys.first] + join_to_path(join[join.keys.first])
      end
    end

    # Override AR Relation dynamic method finder.
    #
    # Afaik ObligationScope does not need to inherit the Relation
    # dynamic methods. This makes debugging typos in this class
    # much easier.
    def method_missing(name, *args)
      raise "Method #{name} does not exist"
    end
  end
end

