# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "declarative_authorization"
  s.version = "0.2.3"

  s.required_ruby_version = ">= 1.8.6"
  s.authors = ["Steffen Bartsch"]
  s.summary = "declarative_authorization is a Rails plugin for authorization based on readable authorization rules."
  s.email = "sbartsch@tzi.org"
  s.files = ["CHANGELOG", "MIT-LICENSE", "README.rdoc", "Rakefile", "authorization_rules.dist.rb", "garlic_example.rb", "init.rb", "app/controllers/authorization_rules_controller.rb", "app/controllers/authorization_usages_controller.rb", "app/helpers/authorization_rules_helper.rb", "app/views/authorization_usages/index.html.erb", "app/views/authorization_rules/index.html.erb", "app/views/authorization_rules/graph.dot.erb", "app/views/authorization_rules/graph.html.erb", "config/routes.rb", "lib/in_controller.rb", "lib/reader.rb", "lib/rails_legacy.rb", "lib/obligation_scope.rb", "lib/in_model.rb", "lib/helper.rb", "lib/authorization.rb", "lib/maintenance.rb", "test/authorization_test.rb", "test/schema.sql", "test/maintenance_test.rb", "test/model_test.rb", "test/controller_test.rb", "test/helper_test.rb", "test/dsl_reader_test.rb", "test/test_helper.rb"]
  s.has_rdoc = true
  s.homepage = %q{http://github.com/stffn/declarative_authorization}

  s.add_dependency('rails', '>= 2.1.0')
end
