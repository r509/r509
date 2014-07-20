$LOAD_PATH.push File.expand_path("../lib", __FILE__)
require "r509/version"

Gem::Specification.new do |s|
  s.name = 'r509'
  s.license = 'Apache 2.0'
  s.version = R509::VERSION
  s.platform = Gem::Platform::RUBY
  s.summary = "A (relatively) simple X.509 certification authority API"
  s.description = 'A module that allows you to create CSRs, issue certs off a CA, view the certs, create CRLs, run an OCSP responder, and much more'
  s.add_development_dependency 'rspec', "~>2.0"
  s.add_development_dependency 'rake'
  s.add_development_dependency 'simplecov'
  s.author = "Paul Kehrer"
  s.email = "paul.l.kehrer@gmail.com"
  s.homepage = "http://r509.org"
  s.required_ruby_version = ">= 1.9.3"
  s.files = %w(README.mdown CONTRIBUTING.mdown LICENSE r509.yaml Rakefile) + Dir["{lib,bin,spec,doc}/**/*"]
  s.executables = ["r509", "r509-parse"]
  s.test_files = Dir.glob('spec/*_spec.rb')
  s.require_path = "lib"
end
