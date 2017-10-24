require 'simplecov'
SimpleCov.start
begin
  require 'coveralls'
  Coveralls.wear!
rescue LoadError
end

$LOAD_PATH.unshift File.expand_path("../../lib", __FILE__)
$LOAD_PATH.unshift File.expand_path("../", __FILE__)
require 'rubygems'
require 'fixtures'
require 'rspec'
require 'r509'

# exclude EC specific tests if it's unsupported
unless R509.ec_supported?
  puts "\e[#{31}mWARNING: NOT RUNNING EC TESTS BECAUSE EC IS UNSUPPORTED ON YOUR RUBY INSTALLATION\e[0m"
  R509.print_debug
  RSpec.configure do |c|
    c.filter_run_excluding :ec => true
  end
end

def ruby_24?
  Gem::Version.new(RUBY_VERSION) >= Gem::Version.new("2.4.0")
end

RSpec.configure do |config|
  config.alias_it_should_behave_like_to :it_validates, "it validates"
end
