$:.push File.expand_path("../lib", __FILE__)  
require "r509/version"  

spec = Gem::Specification.new do |s|
  s.name = 'r509'
  s.version = R509::VERSION
  s.platform = Gem::Platform::RUBY
  s.has_rdoc = false
  s.summary = "A (relatively) simple X.509 certification authority"
  s.description = 'A module that allows you to create CSRs, issue certs off a CA, view the certs, and create CRLs'
  #s.add_dependency 'openssl'
  s.add_development_dependency 'rspec'
  s.add_development_dependency 'syntax'
  s.author = "Paul Kehrer"
  s.email = "paul@victoly.com"
  s.homepage = "http://langui.sh"
  s.required_ruby_version = ">= 1.8.6"
  s.files = %w(README.md r509.yaml Rakefile) + Dir["{lib,script,spec,doc,cert_data}/**/*"]
  s.test_files= Dir.glob('test/*_spec.rb')
  s.require_path = "lib"
end

