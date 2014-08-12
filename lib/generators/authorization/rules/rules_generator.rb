require 'rails/generators'
module Authorization
  class RulesGenerator < Rails::Generators::Base

    source_root File.expand_path('../templates', __FILE__)

    def copy_auth_rules
      
      puts "WARNING - Copying authorization_rules template.  Make sure to back up any existing rules before overwriting."

      copy_file "authorization_rules.rb", "config/authorization_rules.rb"
    end
  end
end