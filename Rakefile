require 'rspec/core/rake_task'

RSpec::Core::RakeTask.new(:spec)
desc 'Build the gem'
task :gem_build do
	`gem build ruby509.gemspec`
end
task :gem_install do
	`gem install ruby509-0.1.gem`
end
task :gem_uninstall do
	`gem uninstall ruby509`
end
