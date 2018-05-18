case ActiveRecord::VERSION::MAJOR
when 3, 4
  adapter_directory = "#{ActiveRecord::VERSION::MAJOR}.#{ActiveRecord::VERSION::MINOR}"
  Dir[File.expand_path("../active_record/#{adapter_directory}/*.rb", __FILE__)].each do |f|
    require f
  end
else
  raise NotImplementedError, "DeclarativeAuthorization does not support Active Record version #{ActiveRecord::VERSION::STRING}"
end
