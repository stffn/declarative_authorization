# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "declarative_authorization"
  s.version = "1.0.0.pre"

  s.required_ruby_version = ">= 2.0.0"
  s.authors = ["Steffen Bartsch"]
  s.summary = "declarative_authorization is a Rails plugin for maintainable authorization based on readable authorization rules."
  s.email = "sbartsch@tzi.org"
  s.files = %w{CHANGELOG MIT-LICENSE README.rdoc Rakefile authorization_rules.dist.rb garlic_example.rb init.rb} + Dir["app/**/*.rb"] + Dir["app/**/*.erb"] + Dir["config/*"] + Dir["lib/*.rb"] + Dir["lib/**/*.rb"] + Dir["lib/tasks/*"] + Dir["test/*"]
  s.has_rdoc = true
  s.extra_rdoc_files = ['README.rdoc', 'CHANGELOG']
  s.homepage = %q{http://github.com/stffn/declarative_authorization}
  s.add_dependency('ruby_parser', '~> 3.6.6')
  s.add_dependency('rails', '>= 4.0.0', '< 4.3.0')
  s.add_development_dependency('test-unit')
end
