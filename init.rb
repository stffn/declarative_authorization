begin
  require File.join(File.dirname(__FILE__), 'lib', 'declarative_authorization') # From here
rescue LoadError
  require 'declarative_authorization' # From gem
end
