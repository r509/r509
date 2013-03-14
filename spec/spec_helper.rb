if (RUBY_VERSION.split('.')[1].to_i > 8 or RUBY_VERSION.split('.')[0].to_i > 1)
  begin
    require 'simplecov'
    SimpleCov.start
  rescue LoadError
  end
end

$:.unshift File.expand_path("../../lib", __FILE__)
$:.unshift File.expand_path("../", __FILE__)
require 'rubygems'
require 'fixtures'
require 'rspec'
require 'r509'

# exclude EC specific tests if it's unsupported
if not R509.ec_supported?
  puts "\e[#{31}mWARNING: NOT RUNNING EC TESTS AS EC IS UNSUPPORTED ON YOUR RUBY INSTALLATION\e[0m"
  R509.print_debug
  RSpec.configure do |c|
    c.filter_run_excluding :ec => true
  end
end
