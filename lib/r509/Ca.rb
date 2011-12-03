require 'openssl'
require 'r509/Config'
require 'r509/Cert'
require 'r509/Exceptions'

module R509
    # Contains the certification authority signing operation methods
    class Ca
    # @param [R509::Config] @config
        def initialize(config)
      @config = config

      unless @config.kind_of?(R509::Config)
        raise R509Error, "config must be a kind of R509::Config"
      end

            self.message_digest= @config.message_digest
        end

        # @param digest [String] New message digest (md5,sha1,sh256,sha512)
        def message_digest=(digest)
            @message_digest = case digest.downcase
                when 'sha1' then OpenSSL::Digest::SHA1.new
                when 'sha256' then OpenSSL::Digest::SHA256.new
                when 'sha512' then OpenSSL::Digest::SHA512.new
                when 'md5' then OpenSSL::Digest::MD5.new
                else OpenSSL::Digest::SHA1.new
            end
        end

        # Signs a CSR
        # @param csr [String,R509::Csr,OpenSSL::X509::Request] The CSR
        # @param profile [String] The profile of the CA you want to use (e.g. "server" in your config)
        # @param subject [Array] subject array to overwrite what's in the CSR
        # @param domains [Array] domain array to add to the subjectAltName (SAN) list
        # @return [R509::Cert] the signed cert object
        def sign_cert(csr,profile,subject=nil,domains=[])
      prof_obj = @config.profile(profile)

            req = OpenSSL::X509::Request.new csr
            san_names = merge_san_domains(req,domains)

            #load ca key and cert
            ca_cert = @config.ca_cert
            ca_key = @config.ca_key

            #generate random serial in accordance with best practices
            #guidelines state 20-bits of entropy, but we can cram more in
            #per rfc5280 conforming CAs can make the serial field up to 20 octets
            serial = OpenSSL::BN.rand(160,0) # 160 bits is 20 bytes (octets).
            #since second param is 0 the most significant bit must always be 1
            #this theoretically gives us 159 bits of entropy

            cert = OpenSSL::X509::Certificate.new
            #not_before will be set to 6 hours before now to prevent issues with bad system clocks (clients don't sync)
            from = Time.now - 6 * 60 * 60
            if(subject.kind_of?(Array)) then
                name = OpenSSL::X509::Name.new subject
                cert.subject = name
            else
                cert.subject = req.subject
            end
            cert.issuer = ca_cert.subject
            cert.not_before = from
            cert.not_after = from + 365 * 24 * 60 * 60
            cert.public_key = req.public_key
            cert.serial =serial
            cert.version = 2 #2 means v3


            basic_constraints = prof_obj.basic_constraints
            key_usage = prof_obj.key_usage
            extended_key_usage = prof_obj.extended_key_usage
            certificate_policies = prof_obj.certificate_policies
            ef = OpenSSL::X509::ExtensionFactory.new
            ef.subject_certificate = cert
            ef.issuer_certificate = ca_cert
            ext = []
            ext << ef.create_extension("basicConstraints", basic_constraints, true)
            ext << ef.create_extension("subjectKeyIdentifier", "hash")
            ext << ef.create_extension("keyUsage", key_usage.join(","))
            ext << ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always")
            if(extended_key_usage.size > 0) then
                ext << ef.create_extension("extendedKeyUsage", extended_key_usage.join(","))
            end
            conf = build_conf('certPolicies',prof_obj.certificate_policies)
            ef.config = OpenSSL::Config.parse(conf)
            #ef.config = OpenSSL::Config.parse(<<-_end_of_cnf_)
            #[certPolicies]
            #CPS.1 = http://www.example.com/cps
            #_end_of_cnf_


            ext << ef.create_extension("certificatePolicies", '@certPolicies')
            if ! san_names.empty? then
                ext << ef.create_extension("subjectAltName", san_names.join(",")) 
            end

            ext << ef.create_extension("crlDistributionPoints", @config.cdp_location)

            if @config.ocsp_location then
            ext << ef.create_extension("authorityInfoAccess",
                        "OCSP;" << @config.ocsp_location)
            end
            cert.extensions = ext
            cert.sign ca_key, @message_digest
            Cert.new cert
        end

        private
        def merge_san_domains(req,domains)
            domains_from_csr = parse_domains_from_csr(req)
            if (domains.kind_of?(Array)) then
                domains = domains.map { |domain| 'DNS: '+domain }
                domains_from_csr.concat(domains).uniq!
            end
            domains_from_csr
        end

        #this code is identical to the method in Csr. think about moving these to a helper class
        def parse_domains_from_csr(req)
            domains_from_csr = []
            begin
                set = OpenSSL::ASN1.decode(req.attributes[0].value) #assuming just one attribute from above, that'd be extReq. this may be unsafe
                seq = set.value[0]
                extensions = seq.value.collect{|asn1ext| OpenSSL::X509::Extension.new(asn1ext).to_a }
                extensions.each { |ext| 
                    domains_from_csr = ext[1].split(',') 
                    domains_from_csr = domains_from_csr.collect {|x| x.strip }
                }
            rescue
            #not sure there's ever a case where a valid CSR has no attr extension at all
            end
            domains_from_csr
        end

        def build_conf(section,data)
            conf = ["[#{section}]"]
            conf.concat data
            conf.join "\n"
        end

    end
end
