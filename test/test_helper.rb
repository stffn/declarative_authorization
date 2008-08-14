require 'test/unit'
RAILS_ROOT = File.dirname(__FILE__) + '../../../../../'
require File.dirname(__FILE__) + '/../lib/authorization.rb'

unless defined?(ActiveRecord)
  if File.directory? RAILS_ROOT + 'config'
    puts 'using config/boot.rb'
    ENV['RAILS_ENV'] = 'test'
    require File.join(RAILS_ROOT, 'config', 'boot.rb')
  else
    # simply use installed gems if available
    puts 'using rubygems'
    require 'rubygems'
    gem 'actionpack'; gem 'activerecord'; gem 'activesupport'
  end

  %w(action_pack active_record active_support).each {|f| require f}
end

class MockDataObject
  def initialize (attrs = {})
    attrs.each do |key, value|
      instance_variable_set(:"@#{key}", value)
      self.class.class_eval do
        attr_reader key
      end
    end
  end
  
  def self.table_name
    "mocks"
  end
end

class MockUser < MockDataObject
  def initialize (*roles)
    options = roles.last.is_a?(::Hash) ? roles.pop : {}
    super(options.merge(:roles => roles))
  end
end

class MockController
  def initialize (reader = nil)
    @authorization_engine = Authorization::Engine.new(reader) if reader
    @called_render = false
    @params = {}
  end
  
  attr_reader :called_render, :action_name, :current_user, :params
  def request! (user, action_name, params = {})
    @called_render = false
    @current_user = user
    @action_name = action_name
    @params = params
    before_filters.each { |block| block.call(self) }
    self
  end
  
  def self.before_filter (&block)
    before_filters << block
  end
  
  @@action_methods = Set.new
  def self.action_methods (*methods)
    @@action_methods = methods.collect {|m| m.to_s}.to_set unless methods.empty?
    @@action_methods
  end
  
  def self.controller_name
    "mock"
  end
  
  def self.before_filters
    write_inheritable_attribute('before_filters', []) unless read_inheritable_attribute('before_filters')
    read_inheritable_attribute('before_filters')
  end
  def before_filters
    self.class.before_filters
  end
  
  def render (*args)
    @called_render = true;
  end
  
  def logger (*args)
    Class.new do 
      def warn(*args)
        #p args
      end
      alias_method :info, :warn
    end.new
  end
end