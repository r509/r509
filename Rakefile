require 'rspec/core/rake_task'

RSpec::Core::RakeTask.new(:spec)
desc 'Run all rspec tests with rcov'
RSpec::Core::RakeTask.new(:rcov) do |t|
	t.rcov_opts =  %q[--exclude "spec,gems"]
	t.rcov = true
end
desc 'Build the gem'
task :gem_build do
	puts `gem build r509.gemspec`
end
task :gem_install do
	puts `gem install r509-0.2.gem`
end
task :gem_uninstall do
	puts `gem uninstall r509`
end
task :default => :spec
