$:.push File.expand_path("../lib", __FILE__)
require "r509/version"

spec = Gem::Specification.new do |s|
  s.name = 'r509'
  s.version = R509::VERSION
  s.platform = Gem::Platform::RUBY
  s.has_rdoc = false
  s.summary = "A (relatively) simple X.509 certification authority"
  s.description = 'A module that allows you to create CSRs, issue certs off a CA, view the certs, create CRLs, run an OCSP responder, and much more'
  #s.add_dependency 'openssl'
  s.add_development_dependency 'rspec'
  s.add_development_dependency 'rake'
  s.author = "Paul Kehrer"
  s.email = "paul.l.kehrer@gmail.com"
  s.homepage = "http://langui.sh"
  s.required_ruby_version = ">= 1.8.6"
  s.files = %w(README.md r509.yaml Rakefile) + Dir["{lib,bin,spec,doc}/**/*"]
  s.executables = ["r509"]
  s.test_files= Dir.glob('test/*_spec.rb')
  s.require_path = "lib"
end

