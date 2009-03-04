# Groups methods and additions that were used but are not readily available in
# all supported Rails versions.
class Hash
  unless {}.respond_to?(:deep_merge)
    # Imported from Rails 2.2
    def deep_merge(other_hash)
      self.merge(other_hash) do |key, oldval, newval|
        oldval = oldval.to_hash if oldval.respond_to?(:to_hash)
        newval = newval.to_hash if newval.respond_to?(:to_hash)
        oldval.class.to_s == 'Hash' && newval.class.to_s == 'Hash' ? oldval.deep_merge(newval) : newval
      end
    end
  end
end