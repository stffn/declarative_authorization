# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "declarative_authorization"
  s.version = "0.4.1"

  s.required_ruby_version = ">= 1.8.6"
  s.authors = ["Steffen Bartsch"]
  s.summary = "declarative_authorization is a Rails plugin for authorization based on readable authorization rules."
  s.email = "sbartsch@tzi.org"
  s.files = ["CHANGELOG", "MIT-LICENSE", "README.rdoc", "Rakefile", "authorization_rules.dist.rb", "garlic_example.rb", "init.rb", "app/controllers/authorization_rules_controller.rb", "app/controllers/authorization_usages_controller.rb", "app/helpers/authorization_rules_helper.rb", "app/views/authorization_usages/index.html.erb", "app/views/authorization_rules/index.html.erb", "app/views/authorization_rules/_show_graph.erb", "app/views/authorization_rules/_change.erb", "app/views/authorization_rules/_suggestions.erb", "app/views/authorization_rules/graph.dot.erb", "app/views/authorization_rules/change.html.erb", "app/views/authorization_rules/graph.html.erb", "config/routes.rb", "lib/declarative_authorization.rb", "lib/declarative_authorization/in_controller.rb", "lib/declarative_authorization/reader.rb", "lib/declarative_authorization/rails_legacy.rb", "lib/declarative_authorization/obligation_scope.rb", "lib/declarative_authorization/in_model.rb", "lib/declarative_authorization/helper.rb", "lib/declarative_authorization/development_support/analyzer.rb", "lib/declarative_authorization/development_support/change_analyzer.rb", "lib/declarative_authorization/development_support/change_supporter.rb", "lib/declarative_authorization/development_support/development_support.rb", "lib/declarative_authorization/authorization.rb", "lib/declarative_authorization/maintenance.rb", "lib/declarative_authorization.rb", "test/authorization_test.rb", "test/schema.sql", "test/maintenance_test.rb", "test/model_test.rb", "test/controller_test.rb", "test/development_support", "test/helper_test.rb", "test/dsl_reader_test.rb", "test/controller_filter_resource_access_test.rb", "test/test_helper.rb"]
  s.has_rdoc = true
  s.extra_rdoc_files = ['README.rdoc', 'CHANGELOG']
  s.homepage = %q{http://github.com/stffn/declarative_authorization}

  s.add_dependency('rails', '>= 2.1.0')
end
