# A module for building an easy to use CA. Includes CSR, Certificate, and CRL support.
module R509
  require('r509/certificate_authority.rb')
  require('r509/csr.rb')
  require('r509/spki.rb')
  require('r509/cert.rb')
  require('r509/crl.rb')
  require('r509/oid_mapper.rb')
  require('r509/ocsp.rb')
  require('r509/config.rb')
  require('r509/private_key.rb')
  require('r509/message_digest.rb')
  require('r509/subject.rb')
  require('r509/validity.rb')
  require('r509/ec-hack.rb')
  require('r509/asn1.rb')
  require('r509/engine.rb')
  require('r509/version.rb')

  # print version information to console
  def self.print_debug
    puts "r509 v#{R509::VERSION}"
    puts OpenSSL::OPENSSL_VERSION
    puts "Ruby #{RUBY_VERSION}-p#{RUBY_PATCHLEVEL}"
    puts "Elliptic curve support: #{self.ec_supported?}"
  end

  def self.ec_supported?
    (not defined?(OpenSSL::PKey::EC::UNSUPPORTED))
  end
end

#add some global mappings we want available throughout r509
R509::OIDMapper.batch_register([
  { :oid => "2.5.4.15", :short_name => "businessCategory" }, # extended validation related
  { :oid => "1.3.6.1.4.1.311.60.2.1.2", :short_name => "jurisdictionOfIncorporationStateOrProvinceName" }, # extended validation related
  { :oid => "1.3.6.1.4.1.311.60.2.1.3", :short_name => "jurisdictionOfIncorporationCountryName" }, # extended validation related
  { :oid => "2.5.29.37.0", :short_name => "anyExtendedKeyUsage", :long_name => "Any Extended Key Usage" } # an EKU older OpenSSL frequently lacks
])
