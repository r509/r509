$:.push File.expand_path("../lib", __FILE__)  
require "ruby509/version"  

spec = Gem::Specification.new do |s|
  s.name = 'ruby509'
  s.version = Ruby509::VERSION
  s.platform = Gem::Platform::RUBY
  s.has_rdoc = false
  s.summary = "A (relatively) simple X.509 certification authority"
  s.description = s.summary
  #s.add_dependency 'openssl'
  s.add_development_dependency 'rspec'
  s.add_development_dependency 'syntax'
  s.author = "Paul Kehrer"
  s.email = "paul@victoly.com"
  s.homepage = "http://langui.sh"
  s.required_ruby_version = ">= 1.8.7"
  s.files = %w(README ruby509.yaml) + Dir["{lib,test,cert_data}/**/*"]
  s.test_file= "test/rspec.rb"
  s.require_path = "lib"
end

