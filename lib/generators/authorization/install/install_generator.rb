require 'rails/generators'
module Authorization
  class InstallGenerator < Rails::Generators::Base
    
    include Rails::Generators::Migration
    source_root File.expand_path('../templates', __FILE__)

    argument :name, type: :string, default: "User"
    argument :attributes, type: :array, default: ['name:string'], banner: "field[:type] field[:type]"
    class_option :create_user, type: :boolean, default: false, desc: "Skips the creation of a new User model.  Use if the model already exists."
    class_option :commit, type: :boolean, default: false, desc: "Performs rake tasks such as migrate and seed."

    def self.next_migration_number dirname
      if ActiveRecord::Base.timestamped_migrations
        Time.now.utc.strftime("%Y%m%d%H%M%S")
      else
        "%.3d" % (current_migration_number(dirname) + 1)
      end
    end

    def install_decl_auth
      habtm_table_name  = "#{name.pluralize}" <= "Roles" ? "#{name.pluralize}Roles" : "Roles#{name.pluralize}"
      habtm_file_glob  = "#{name.pluralize}" <= "Roles" ? 'db/migrate/*create_*_roles*' : 'db/migrate/*create_roles_*'

      generate 'model', "#{name} #{attributes.join(' ')}" if options[:create_user]
      generate 'model', 'Role title:string'

      generate 'migration', "Create#{habtm_table_name} #{name.downcase}:integer role:integer"
      gsub_file Dir.glob(habtm_file_glob).last, 'integer', 'references'
      inject_into_file Dir.glob(habtm_file_glob).last, ", id: false", before: ' do |t|'

      rake 'db:migrate' if options[:commit]

      inject_into_file "app/models/role.rb", "  has_and_belongs_to_many :#{name.downcase.pluralize}\n", after: "ActiveRecord::Base\n"

      inject_into_file "app/models/#{name.singularize.downcase}.rb", "  has_and_belongs_to_many :roles\n", after: "ActiveRecord::Base\n"
      inject_into_file "app/models/#{name.singularize.downcase}.rb", before: "\nend" do <<-'RUBY'


  def role_symbols
    (roles || []).map {|r| r.title.to_sym}
  end
RUBY
      end

      inject_into_file 'db/seeds.rb', after: ".first)\n" do <<-'RUBY'

roles = Role.create([
  {title: 'admin'},
  {title: 'user'}
]) if Role.count == 0
RUBY
      end

      rake 'db:seed' if options[:commit]

      generate 'authorization:rules'
      puts "Please run `rake db:migrate` and `rake db:seed` to finish installing." unless options[:commit]
    end
  end
end






#       @flavor = self.flavor
#       if @flavor == "auto"
#         puts "\nWelcome to Caseadilla! Please enter a flavor to install:"
#         puts "\n[steak] This is recommended for a fresh Rails app.  Caseadilla will set up Devise and Declarative Authorization for you, along with an admin user and various authorization roles."
#         puts "\n[chicken] Select this if you have auth in place already or plan to use something other than Devise or Declarative Authorization.  Caseadilla will use methods such as `current_user.is_admin?` to help with auth integration.  See the readme for more details."
#         puts "\n[veggie] This flavor will install Caseadilla as minimally as possible, without any auth support.  You will be responsible for implementing authorization and authentication into Caseadilla.\n\n"
#         flavor_choice = STDIN.gets.chomp
#         @flavor = flavor_choice
#       end

#       case @flavor
#       when "steak"
#         @target = "steak"

#         gem 'devise'
#         gem 'declarative_authorization', git: 'git://github.com/zeiv/declarative_authorization'
#         Bundler.with_clean_env do
#           run 'bundle install'
#         end

#         generate 'devise:install'
#         generate 'devise', 'User'
#         rake 'db:migrate'

#         migration_template 'steak/db/migrate/add_name_to_users.rb', "db/migrate/add_name_to_users.rb"
#         rake 'db:migrate'

#         inject_into_file 'app/helpers/application_helper.rb', after: "module ApplicationHelper\n" do <<-'RUBY'
#   def resource_name
#     :user
#   end

#   def resource
#     @resource ||= User.new
#   end

#   def devise_mapping
#     @devise_mapping ||= Devise.mappings[:user]
#   end
#         RUBY
#         end

#         inject_into_file 'app/controllers/application_controller.rb', after: "ActionController::Base\n" do <<-'RUBY'
#   before_action :configure_permitted_parameters, if: :devise_controller?

#         RUBY
#         end

#         inject_into_file 'app/controllers/application_controller.rb', before: "\nend" do <<-'RUBY'


#   protected

#   def configure_permitted_parameters
#     devise_parameter_sanitizer.for(:account_update) << [:first_name, :last_name, :time_zone]
#   end
#         RUBY
#         end
#       when "chicken"
#         @target = "chicken"
#       when "veggie"
#         @target = "veggie"
#       else
#         puts "That flavor is not recognized.  Please enter steak, chicken, or veggie.  E.g., for a full install use `rails g caseadilla:install steak`"
#       end
#     end

#     def flavor_files
#       copy_file "#{@target}/config/initializers/caseadilla.rb", "config/initializers/caseadilla.rb"
#     end

#     def common_files
#       puts "*** WARNING - Generating configuration files. Make sure you have backed up any files before overwriting them. ***"

#       #config helper
#       copy_file "app/helpers/caseadilla/config_helper.rb", "app/helpers/caseadilla/config_helper.rb"

#       #initial view partials
#       copy_file "app/views/caseadilla/layouts/_tab_navigation.html.erb", "app/views/caseadilla/layouts/_tab_navigation.html.erb"
#       copy_file "app/views/caseadilla/layouts/_top_navigation.html.erb", "app/views/caseadilla/layouts/_top_navigation.html.erb"

#       #blank stylesheets and JavaScript files
#       copy_file "app/assets/stylesheets/caseadilla/custom.css.scss", "app/assets/stylesheets/caseadilla/custom.css.scss"
#       copy_file "app/assets/javascripts/caseadilla/custom.js", "app/assets/javascripts/caseadilla/custom.js"
#     end

#     def copy_robots
#       puts " ** Overwrite if you haven't yet modified your robots.txt, otherwise add disallow rules for /caseadilla and /admin manually **"
#       copy_file "public/robots.txt", "public/robots.txt"
#     end

#     # protected
#     # attr_reader :flavor

#     # def assign_flavor!(f)
#     #   @flavor = f
#     # end
#   end
# end