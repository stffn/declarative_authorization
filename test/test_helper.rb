require 'pathname'

ENV['RAILS_ENV'] = 'test'

require 'bundler/setup'
begin
  # rails 3
  require 'rails/all'
rescue LoadError
  # rails 2.3
  %w(active_support action_pack action_controller active_record initializer).each {|f| require f}
end
Bundler.require

if Rails.version >= '4.1'
  require 'minitest/autorun'
  require 'test_support/minitest_compatibility'
else
  require 'test/unit'
end

# rails 2.3 and ruby 1.9.3 fix
MissingSourceFile::REGEXPS.push([/^cannot load such file -- (.+)$/i, 1])

# Silence Rails 4 deprecation warnings in test suite
# TODO: Model.scoped is deprecated
# TODO: Eager loading Post.includes(:comments).where("comments.title = 'foo'") becomes Post.includes(:comments).where("comments.title = 'foo'").references(:comments)
# if Rails.version >= '4'
#   ActiveSupport::Deprecation.silenced = true
# end

puts "Testing against rails #{Rails::VERSION::STRING}"

RAILS_ROOT = File.dirname(__FILE__)

DA_ROOT = Pathname.new(File.expand_path("..", File.dirname(__FILE__)))

require DA_ROOT + File.join(%w{lib declarative_authorization rails_legacy})
require DA_ROOT + File.join(%w{lib declarative_authorization authorization})
require DA_ROOT + File.join(%w{lib declarative_authorization in_controller})
require DA_ROOT + File.join(%w{lib declarative_authorization maintenance})

begin
  require 'ruby-debug'
rescue MissingSourceFile; end

if Rails::VERSION::MAJOR == 2 && RUBY_VERSION >= '2.0.0'
  module ActiveRecord
    module Associations
      class AssociationProxy
        def send(method, *args)
          if proxy_respond_to?(method, true)
            super
          else
            load_target
            @target.send(method, *args)
          end
        end
      end
    end
  end
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
    raise StandardError, "Couldn't find #{self.name} with id #{args[0].inspect}" unless args[0]
    new :id => args[0]
  end

  def self.find_or_initialize_by(args)
    raise StandardError, "Syntax error: find_or_initialize by expects a hash: User.find_or_initialize_by(:id => @user.id)" unless args.is_a?(Hash)
    new :id => args[:id]
  end
end

class MockUser < MockDataObject
  def initialize (*roles)
    options = roles.last.is_a?(::Hash) ? roles.pop : {}
    super({:role_symbols => roles, :login => hash}.merge(options))
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

if Rails.version < "3"
  ActiveRecord::Base.establish_connection({:adapter => 'sqlite3', :database => ':memory:'})
  ActionController::Routing::Routes.draw do |map|
    map.connect ':controller/:action/:id'
  end
else
  class TestApp
    class Application < ::Rails::Application
      config.secret_key_base = "testingpurposesonly"
      config.active_support.deprecation = :stderr
      database_path = File.expand_path('../database.yml', __FILE__)
      if Rails.version.start_with? '3.0.'
        config.paths.config.database database_path
      else
        config.paths['config/database'] = database_path
      end
      initialize!
    end
  end
  class ApplicationController < ActionController::Base
  end
  #Rails::Application.routes.draw do
  if Rails.version.start_with? '4'
    Rails.application.routes.draw do
      match '/name/spaced_things(/:action)' => 'name/spaced_things', :via => [:get, :post, :put, :patch, :delete]
      match '/deep/name_spaced/things(/:action)' => 'deep/name_spaced/things', :via => [:get, :post, :put, :patch, :delete]
      match '/:controller(/:action(/:id))', :via => [:get, :post, :put, :patch, :delete]
    end
    class TestApp
      class Application < ::Rails::Application
        config.secret_key_base = 'thisstringdoesnothing'
      end
    end
  else
    Rails.application.routes.draw do
      match '/name/spaced_things(/:action)' => 'name/spaced_things'
      match '/deep/name_spaced/things(/:action)' => 'deep/name_spaced/things'
      match '/:controller(/:action(/:id))'
    end
  end
end

ActionController::Base.send :include, Authorization::AuthorizationInController
if Rails.version < "3"
  require "action_controller/test_process"
end


if Rails.version < "4"
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

    unless Rails.version < "3"
      def setup
        #@routes = Rails::Application.routes
        @routes = Rails.application.routes
      end
    end
  end

elsif Rails.version < '4.1'
  class Test::Unit::TestCase
    include Authorization::TestHelper
  end

  class ActiveSupport::TestCase
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

    unless Rails.version < "3"
      def setup
        #@routes = Rails::Application.routes
        @routes = Rails.application.routes
      end
    end
  end
else
  module Test
    module Unit
    end
  end

  class Test::Unit::TestCase < Minitest::Test
    include Authorization::TestHelper
  end

  class ActiveSupport::TestCase
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

    unless Rails.version < "3"
      def setup
        #@routes = Rails::Application.routes
        @routes = Rails.application.routes
      end
    end
  end
end
