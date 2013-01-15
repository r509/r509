if (RUBY_VERSION.split('.')[1].to_i > 8)
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
