garlic do
  repo 'rails', :url => 'git://github.com/rails/rails'#, :local => "~/dev/vendor/rails"
  repo 'declarative_authorization', :path => '.'

  target 'edge'
  target '2.1-stable', :branch => 'origin/2-1-stable'
  target '2.2.0-RC1', :tag => 'v2.2.0'

  all_targets do
    prepare do
      plugin 'declarative_authorization', :clone => true
    end

    run do
      cd "vendor/plugins/declarative_authorization" do
        sh "rake"
      end
    end
  end
end
