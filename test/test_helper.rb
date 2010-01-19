require 'test/unit'
RAILS_ROOT = File.join(File.dirname(__FILE__), %w{.. .. .. ..})
require File.join(File.dirname(__FILE__), %w{.. lib declarative_authorization rails_legacy})
require File.join(File.dirname(__FILE__), %w{.. lib declarative_authorization authorization})
require File.join(File.dirname(__FILE__), %w{.. lib declarative_authorization in_controller})
require File.join(File.dirname(__FILE__), %w{.. lib declarative_authorization maintenance})

unless defined?(ActiveRecord)
  if File.directory? RAILS_ROOT + '/config'
    puts 'using config/boot.rb'
    ENV['RAILS_ENV'] = 'test'
    require File.join(RAILS_ROOT, 'config', 'boot.rb')
  else
    # simply use installed gems if available
    puts 'using rubygems'
    require 'rubygems'
    gem 'actionpack'; gem 'activerecord'; gem 'activesupport'; gem 'rails'
  end

  %w(action_pack action_controller active_record active_support initializer).each {|f| require f}
end

begin
  require 'ruby-debug'
rescue MissingSourceFile; end


class MockDataObject
  def initialize (attrs = {})
    attrs.each do |key, value|
      instance_variable_set(:"@#{key}", value)
      self.class.class_eval do
        attr_reader key
      end
    end
  end
  
  def self.descends_from_active_record?
    true
  end

  def self.table_name
    name.tableize
  end

  def self.name
    "Mock"
  end
  
  def self.find(*args)
    raise "Couldn't find #{self.name} with id #{args[0].inspect}" unless args[0]
    new :id => args[0]
  end
end

class MockUser < MockDataObject
  def initialize (*roles)
    options = roles.last.is_a?(::Hash) ? roles.pop : {}
    super(options.merge(:role_symbols => roles, :login => hash))
  end

  def initialize_copy (other)
    @role_symbols = @role_symbols.clone
  end
end

class MocksController < ActionController::Base
  attr_accessor :current_user
  attr_writer :authorization_engine
  
  def authorized?
    !!@authorized
  end
  
  def self.define_action_methods (*methods)
    methods.each do |method|
      define_method method do
        @authorized = true
        render :text => 'nothing'
      end
    end
  end

  def self.define_resource_actions
    define_action_methods :index, :show, :edit, :update, :new, :create, :destroy
  end
  
  def logger (*args)
    Class.new do 
      def warn(*args)
        #p args
      end
      alias_method :info, :warn
      alias_method :debug, :warn
      def warn?; end
      alias_method :info?, :warn?
      alias_method :debug?, :warn?
    end.new
  end
end

ActionController::Routing::Routes.draw do |map|
  map.connect ':controller/:action/:id'
end
ActionController::Base.send :include, Authorization::AuthorizationInController
require "action_controller/test_process"

class Test::Unit::TestCase
  include Authorization::TestHelper
  
  def request! (user, action, reader, params = {})
    action = action.to_sym if action.is_a?(String)
    @controller.current_user = user
    @controller.authorization_engine = Authorization::Engine.new(reader)
    
    ((params.delete(:clear) || []) + [:@authorized]).each do |var|
      @controller.instance_variable_set(var, nil)
    end
    get action, params
  end
end
