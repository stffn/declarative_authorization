require 'rake'
require 'rake/testtask'
require 'rake/rdoctask'

desc 'Default: run unit tests.'
task :default => :test

desc 'Test the authorization plugin.'
Rake::TestTask.new(:test) do |t|
  t.libs << 'lib'
  t.pattern = 'test/**/*_test.rb'
  t.verbose = true
end

desc 'Generate documentation for the authorization plugin.'
Rake::RDocTask.new(:rdoc) do |rdoc|
  rdoc.rdoc_dir = 'rdoc'
  rdoc.title    = 'Authorization'
  rdoc.options << '--line-numbers' << '--inline-source'
  rdoc.options << '--charset' << 'utf-8'
  rdoc.rdoc_files.include('README.rdoc')
  rdoc.rdoc_files.include('CHANGELOG')
  rdoc.rdoc_files.include('lib/**/*.rb')
end

# load up garlic if it's here
if File.directory?(File.join(File.dirname(__FILE__), 'garlic'))
  require File.join(File.dirname(__FILE__), 'garlic/lib/garlic_tasks')
  require File.join(File.dirname(__FILE__), 'garlic')
end

desc "clone the garlic repo (for running ci tasks)"
task :get_garlic do
  sh "git clone git://github.com/ianwhite/garlic.git garlic"
end

desc "Expand filelist in src gemspec"
task :build_gemspec do
  gemspec_data = File.read("declarative_authorization.gemspec.src")
  gemspec_data.gsub!(/\.files = (.*)/) {|m| ".files = #{eval($1).inspect}"}
  File.open("declarative_authorization.gemspec", "w") {|f| f.write(gemspec_data)}
end

