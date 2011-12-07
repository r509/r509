require 'openssl'
require 'r509/Config'

module R509::Helper
    class FirstConfigMatch
        def self.match(certid,configs)
            configs.each do |config|
                root_certid = OpenSSL::OCSP::CertificateId.new(config.ca_cert,config.ca_cert)
                if certid.cmp_issuer(root_certid) then
                    return config
                end
            end
            #if no match return nil
            nil
        end
    end
end
