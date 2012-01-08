# A module for building an easy to use CA. Includes CSR, Certificate, and CRL support.
module R509
    autoload :CertificateAuthority, 'r509/certificateauthority.rb'
    autoload :Csr, 'r509/csr.rb'
    autoload :Spki, 'r509/spki.rb'
    autoload :Cert, 'r509/cert.rb'
    autoload :Crl, 'r509/crl.rb'
    autoload :OidMapper, 'r509/oidmapper.rb'
    autoload :Ocsp, 'r509/ocsp.rb'
    autoload :Config, 'r509/config.rb'
    autoload :PrivateKey, 'r509/privatekey.rb'
    autoload :MessageDigest, 'r509/messagedigest.rb'
    autoload :Subject, 'r509/subject.rb'
    autoload :Validity, 'r509/validity.rb'
end

#add some global mappings we want available throughout r509
R509::OidMapper.batch_register([
    { :oid => "2.5.4.15", :short_name => "businessCategory" },
    { :oid => "1.3.6.1.4.1.311.60.2.1.2", :short_name => "jurisdictionOfIncorporationStateOrProvinceName" },
    { :oid => "1.3.6.1.4.1.311.60.2.1.3", :short_name => "jurisdictionOfIncorporationCountryName" }
])
