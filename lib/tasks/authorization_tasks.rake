namespace :auth do
  desc "Lists all privileges used in controllers, views, models"
  task :used_privileges do
    # TODO note where privileges are used
    require File.join(RAILS_ROOT, 'config', 'boot.rb')
    require File.join(RAILS_ROOT, 'config', 'environment.rb')
    controllers = [ApplicationController]
    Dir.new("#{RAILS_ROOT}/app/controllers").entries.each do |controller_file|
      if controller_file =~ /_controller/ 
        controllers << controller_file.gsub(".rb","").camelize.constantize
      end
    end 
    perms = controllers.select {|c| c.send(:class_variable_defined?, :@@permissions)}.
                        inject([]) do |all, c|
      contr_context = c.name.sub("Controller", "").tableize.to_sym
      contr_perms = c.send(:class_variable_get, :@@permissions).collect do |cp|
        [cp.privilege, cp.context || contr_context, cp]
      end
      if contr_perms.any? {|cp| cp[0].nil?}
        contr_perms += c.send(:action_methods).collect {|am| am.to_sym}.
                         reject {|am| contr_perms.any? {|cp| cp[2].actions.include?(am)}}.
                         collect {|am| [am, contr_context]}
      end
      all += contr_perms.reject {|cp| cp[0].nil?}.collect {|cp| cp[0..1]}
    end
    
    model_files = `grep -l "^[[:space:]]*using_access_control" #{RAILS_ROOT}/app/models/*.rb`.split("\n")
    models_with_ac = model_files.collect {|mf| mf.sub(/^.*\//, "").sub(".rb", "").tableize.to_sym}
    model_security_privs = [:create, :read, :update, :delete]
    models_with_ac.each {|m| perms += model_security_privs.collect{|msp| [msp, m]}}

    grep_file_pattern = "#{RAILS_ROOT}/app/models/*.rb #{RAILS_ROOT}/app/views/**/* #{RAILS_ROOT}/app/controllers/*.rb"
    `grep "permitted_to?" #{grep_file_pattern}`.split("\n").each do |ptu|
      file, grep_match = ptu.split(':', 2)
      context = privilege = nil
      if (match = grep_match.match(/permitted_to\?\(?\s*:(\w+),\s*(:?@?\w+)/))
        privilege = match[1].to_sym
        if match[2][0..0] == ':'
          context = match[2][1..-1].to_sym
        else
          c = (match[2][0..0] == '@' ? match[2][1..-1] : match[2]).pluralize.to_sym
          context = c if perms.any? {|p| p[1] == c}
        end
      end
      if privilege.nil? or context.nil?
        puts "Could not handle: #{ptu}"
      else
        perms << [privilege, context]
      end
    end
    
    `grep ".with_permissions_to" #{grep_file_pattern}`.split("\n").each do |wpt|
      file, grep_match = wpt.split(':', 2)
      context = privilege = nil
      if match = grep_match.match(/(\w+\.)?with_permissions_to(\(:\w+)?/)
        c = match[1][0..-2].tableize.to_sym if match[1]
        c ||= File.basename(file, '.rb').tableize.to_sym
        context = c if perms.any? {|p| p[1] == c}
        privilege = match[2] && match[2][(match[2][0..0]=='(' ? 2 : 1)..-1].to_sym
        privilege ||= :read
      end
      if privilege.nil? or context.nil?
        puts "Could not handle: #{ptu}"
      else
        perms << [privilege, context]
      end
    end
    
    perms.uniq!
    perm_hash = {}
    perms.each do |cp| 
      perm_hash[cp[1]] ||= []
      perm_hash[cp[1]] << cp[0]
    end

    puts "Privileges currently in use:"
    perm_hash.each do |context, privileges|
      puts "  #{context.inspect}:\t#{privileges.collect {|p| p.inspect}.sort * ', '}"
      #privileges.collect {|p| p.inspect}.sort.each {|p| puts "  #{p}"}
    end
  end
end
