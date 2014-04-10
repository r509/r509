require 'rubygems'
require 'rspec/core/rake_task'
require "#{File.dirname(__FILE__)}/lib/r509/version"

task :default => :spec
RSpec::Core::RakeTask.new(:spec)

# define a new spec with suppressed stack trace
RSpec::Core::RakeTask.new(:ntspec) do |t|
  t.fail_on_error = false
end

namespace :gem do
  desc 'Build the gem'
  task :build do
    puts `yard`
    puts `gem build r509.gemspec`
  end

  desc 'Install gem'
  task :install do
    puts `gem install r509-#{R509::VERSION}.gem`
  end

  desc 'Uninstall gem'
  task :uninstall do
    puts `gem uninstall r509`
  end
end

desc "Open an irb session with the lib dir included"
task :irb do
  $:.unshift File.expand_path("../../lib", __FILE__)
  $:.unshift File.expand_path("../", __FILE__)
  require 'r509'
  require 'irb'
  ARGV.clear
  IRB.start
end


desc 'Build yard documentation'
task :yard do
  puts `yard`
  `open doc/index.html`
end
require 'rubocop/rake_task'

desc 'Run RuboCop on the lib directory'
Rubocop::RakeTask.new(:rubocop) do |task|
  task.patterns = ['lib/**/*.rb']
  # only show the files with failures
#  task.formatters = ['files']
  # don't abort rake on failure
  task.fail_on_error = false
end
