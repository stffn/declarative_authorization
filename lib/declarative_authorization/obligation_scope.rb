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
  # After successfully parsing an obligation, all of the stored paths and conditions are converted
  # into scope options (stored in +proxy_options+ as +:joins+ and +:conditions+).  The resulting
  # scope may then be used to find all scoped objects for which at least one of the parsed
  # obligations is fully met.
  #
  # +@proxy_options[:joins] = { :bar => { :baz => :foo } }
  # @proxy_options[:conditions] = [ 'foos_bazzes.attr = :foos_bazzes__id_0', { :foos_bazzes__id_0 => 1 } ]+
  #
  class ObligationScope < ActiveRecord::NamedScope::Scope
    
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
    def follow_path( steps, past_steps = [] )
      if steps.is_a?( Hash )
        steps.each do |step, next_steps|
          path_to_this_point = [past_steps, step].flatten
          reflection = reflection_for( path_to_this_point ) rescue nil
          if reflection
            follow_path( next_steps, path_to_this_point )
          else
            follow_comparison( next_steps, past_steps, step )
          end
        end
      elsif steps.is_a?( Array ) && steps.length == 2
        if reflection_for( past_steps )
          follow_comparison( steps, past_steps, :id )
        else
          follow_comparison( steps, past_steps[0..-2], past_steps[-1] )
        end
      else
        raise "invalid obligation path #{[past_steps, steps].inspect}"
      end
    end
    
    # At the end of every association path, we expect to see a comparison of some kind; for
    # example, +:attr => [ :is, :value ]+.
    #
    # This method parses the comparison and creates an obligation condition from it.
    def follow_comparison( steps, past_steps, attribute )
      operator = steps[0]
      value = steps[1..-1]
      value = value[0] if value.length == 1

      add_obligation_condition_for( past_steps, [attribute, operator, value] )
    end
    
    # Adds the given expression to the current obligation's indicated path's conditions.
    #
    # Condition expressions must follow the format +[ <attribute>, <operator>, <value> ]+.
    def add_obligation_condition_for( path, expression )
      raise "invalid expression #{expression.inspect}" unless expression.is_a?( Array ) && expression.length == 3
      add_obligation_join_for( path )
      obligation_conditions[@current_obligation] ||= {}
      ( obligation_conditions[@current_obligation][path] ||= Set.new ) << expression
    end
    
    # Adds the given path to the list of obligation joins, if we haven't seen it before.
    def add_obligation_join_for( path )
      map_reflection_for( path ) if reflections[path].nil?
    end
    
    # Returns the model associated with the given path.
    def model_for (path)
      reflection = reflection_for(path)
      
      if reflection.respond_to?(:proxy_reflection)
        reflection.proxy_reflection.klass
      elsif reflection.respond_to?(:klass)
        reflection.klass
      else
        reflection
      end
    end
    
    # Returns the reflection corresponding to the given path.
    def reflection_for(path, for_join_table_only = false)
      @join_table_joins << path if for_join_table_only and !reflections[path]
      reflections[path] ||= map_reflection_for( path )
    end
    
    # Returns a proper table alias for the given path.  This alias may be used in SQL statements.
    def table_alias_for( path )
      table_aliases[path] ||= map_table_alias_for( path )
    end

    # Attempts to map a reflection for the given path.  Raises if already defined.
    def map_reflection_for( path )
      raise "reflection for #{path.inspect} already exists" unless reflections[path].nil?

      reflection = path.empty? ? @proxy_scope : begin
        parent = reflection_for( path[0..-2] )
        if !parent.respond_to?(:proxy_reflection) and parent.respond_to?(:klass)
          parent.klass.reflect_on_association( path.last )
        else
          parent.reflect_on_association( path.last )
        end
      rescue
        parent.reflect_on_association( path.last )
      end
      raise "invalid path #{path.inspect}" if reflection.nil?

      reflections[path] = reflection
      map_table_alias_for( path )  # Claim a table alias for the path.

      # Claim alias for join table
      if !reflection.respond_to?(:proxy_scope) and reflection.is_a?(ActiveRecord::Reflection::ThroughReflection)
        join_table_path = path[0..-2] + [reflection.options[:through]]
        reflection_for(join_table_path, true)
      end
      
      reflection
    end

    # Attempts to map a table alias for the given path.  Raises if already defined.
    def map_table_alias_for( path )
      return "table alias for #{path.inspect} already exists" unless table_aliases[path].nil?
      
      reflection = reflection_for( path )
      table_alias = reflection.table_name
      if table_aliases.values.include?( table_alias )
        max_length = reflection.active_record.connection.table_alias_length
        # Rails seems to pluralize reflection names
        table_alias = "#{reflection.name.to_s.pluralize}_#{reflection.active_record.table_name}".to(max_length-1)
      end            
      while table_aliases.values.include?( table_alias )
        if table_alias =~ /\w(_\d+?)$/
          table_index = $1.succ
          table_alias = "#{table_alias[0..-(table_index.length+1)]}_#{table_index}"
        else
          table_alias = "#{table_alias[0..(max_length-3)]}_2" 
        end
      end
      table_aliases[path] = table_alias
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
      used_paths = Set.new
      delete_paths = Set.new
      obligation_conditions.each_with_index do |array, obligation_index|
        obligation, conditions = array
        obligation_conds = []
        conditions.each do |path, expressions|
          model = model_for( path )
          table_alias = table_alias_for(path)
          parent_model = (path.length > 1 ? model_for(path[0..-2]) : @proxy_scope)
          expressions.each do |expression|
            attribute, operator, value = expression
            # prevent unnecessary joins:
            if attribute == :id and operator == :is and parent_model.columns_hash["#{path.last}_id"]
              attribute_name = :"#{path.last}_id"
              attribute_table_alias = table_alias_for(path[0..-2])
              used_paths << path[0..-2]
              delete_paths << path
            else
              attribute_name = model.columns_hash["#{attribute}_id"] && :"#{attribute}_id" ||
                               model.columns_hash[attribute.to_s]    && attribute ||
                               :id
              attribute_table_alias = table_alias
              used_paths << path
            end
            bindvar = "#{attribute_table_alias}__#{attribute_name}_#{obligation_index}".to_sym

            sql_attribute = "#{connection.quote_table_name(attribute_table_alias)}.#{connection.quote_table_name(attribute_name)}"
            if value.nil? and [:is, :is_not].include?(operator)
              obligation_conds << "#{sql_attribute} IS #{[:contains, :is].include?(operator) ? '' : 'NOT '}NULL"
            else
              attribute_operator = case operator
                                   when :contains, :is             then "= :#{bindvar}"
                                   when :does_not_contain, :is_not then "<> :#{bindvar}"
                                   when :is_in, :intersects_with   then "IN (:#{bindvar})"
                                   when :is_not_in                 then "NOT IN (:#{bindvar})"
                                   else raise AuthorizationUsageError, "Unknown operator: #{operator}"
                                   end
              obligation_conds << "#{sql_attribute} #{attribute_operator}"
              binds[bindvar] = attribute_value(value)
            end
          end
        end
        obligation_conds << "1=1" if obligation_conds.empty?
        conds << "(#{obligation_conds.join(' AND ')})"
      end
      (delete_paths - used_paths).each {|path| reflections.delete(path)}
      @proxy_options[:conditions] = [ conds.join( " OR " ), binds ]
    end

    def attribute_value (value)
      value.class.respond_to?(:descends_from_active_record?) && value.class.descends_from_active_record? && value.id ||
        value.is_a?(Array) && value[0].class.respond_to?(:descends_from_active_record?) && value[0].class.descends_from_active_record? && value.map( &:id ) ||
        value
    end
    
    # Parses all of the defined obligation joins and defines the scope's :joins or :includes option.
    # TODO: Support non-linear association paths.  Right now, we just break down the longest path parsed.
    def rebuild_join_options!
      joins = (@proxy_options[:joins] || []) + (@proxy_options[:includes] || [])

      reflections.keys.each do |path|
        next if path.empty? or @join_table_joins.include?(path)

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

      case obligation_conditions.length
      when 0 then
        # No obligation conditions means we don't have to mess with joins or includes at all.
      when 1 then
        @proxy_options[:joins] = joins
        @proxy_options.delete( :include )
      else
        @proxy_options.delete( :joins )
        @proxy_options[:include] = joins
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
  end
end