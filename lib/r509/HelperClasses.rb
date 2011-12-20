require 'openssl'
require 'r509/Config'

# Module to hold helper classes
module R509::Helper
    #helper class used to return the first matching config
    class FirstConfigMatch
        # @return [R509::Config::CaConfig]
        def self.match(certid,configs)
            configs.each do |config|
                root_certid = OpenSSL::OCSP::CertificateId.new(config.ca_cert.cert,config.ca_cert.cert)
                if certid.cmp_issuer(root_certid) then
                    return config
                end
            end
            #if no match return nil
            nil
        end
    end
end
