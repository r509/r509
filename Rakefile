require 'rspec/core/rake_task'

task :default => :spec
RSpec::Core::RakeTask.new(:spec)

desc 'Run all rspec tests with rcov'
RSpec::Core::RakeTask.new(:rcov) do |t|
	t.rcov_opts =  %q[--exclude "spec,gems"]
	t.rcov = true
end

desc 'Build the gem'
task :gem_build do
	puts `yard`
	puts `gem build r509.gemspec`
end

desc 'Install gem'
task :gem_install do
	puts `gem install r509-0.2.gem`
end

desc 'Uninstall gem'
task :gem_uninstall do
	puts `gem uninstall r509`
end

desc 'Build yard documentation'
task :yard do
	puts `yard`
	`open doc/index.html`
end
