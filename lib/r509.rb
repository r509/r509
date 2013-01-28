# A module for building an easy to use CA. Includes CSR, Certificate, and CRL support.
module R509
  require('r509/certificateauthority.rb')
  require('r509/csr.rb')
  require('r509/spki.rb')
  require('r509/cert.rb')
  require('r509/crl.rb')
  require('r509/oidmapper.rb')
  require('r509/ocsp.rb')
  require('r509/config.rb')
  require('r509/privatekey.rb')
  require('r509/messagedigest.rb')
  require('r509/subject.rb')
  require('r509/validity.rb')
  require('r509/hmac.rb')
  require('r509/ec-hack.rb')
  require('r509/version.rb')
end

#add some global mappings we want available throughout r509
R509::OidMapper.batch_register([
  { :oid => "2.5.4.15", :short_name => "businessCategory" },
  { :oid => "1.3.6.1.4.1.311.60.2.1.2", :short_name => "jurisdictionOfIncorporationStateOrProvinceName" },
  { :oid => "1.3.6.1.4.1.311.60.2.1.3", :short_name => "jurisdictionOfIncorporationCountryName" }
])
