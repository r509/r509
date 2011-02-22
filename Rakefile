require 'rspec/core/rake_task'

RSpec::Core::RakeTask.new(:spec)
desc 'Build the gem'
task :gem_build do
	puts `gem build ruby509.gemspec`
end
task :gem_install do
	puts `gem install ruby509-0.1.gem`
end
task :gem_uninstall do
	puts `gem uninstall ruby509`
end
task :default => :spec
