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
    module CsrHelper
        # @return [Hash] attributes of a CSR (used by Ca and Csr)
        def parse_attributes_from_csr(req)
            attributes = Hash.new
            domains_from_csr = []
            set = nil
            req.attributes.each { |attribute|
                if attribute.oid == 'extReq' then
                set = OpenSSL::ASN1.decode attribute.value
                end
            }
            if !set.nil? then
                set.value.each { |set_value|
                    @seq = set_value
                    extensions = @seq.value.collect{|asn1ext| OpenSSL::X509::Extension.new(asn1ext).to_a }
                    extensions.each { |ext|
                        hash = {'value' => ext[1], 'critical'=> ext[2] }
                        attributes[ext[0]] = hash
                        if ext[0] == 'subjectAltName' then
                            domains_from_csr = ext[1].gsub(/DNS:/,'').split(',')
                            domains_from_csr = domains_from_csr.collect {|x| x.strip }
                            attributes[ext[0]] = domains_from_csr
                        end
                    }
                }
            end
            attributes
        end
    end
end
