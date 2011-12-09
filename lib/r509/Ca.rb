require 'openssl'
require 'r509/Config'
require 'r509/Cert'
require 'r509/Exceptions'
require 'r509/HelperClasses'

module R509
    # Contains the certification authority signing operation methods
    class Ca
        include R509::Helper::CsrHelper

        # @param [R509::Config] @config
        def initialize(config)
            @config = config

            unless @config.kind_of?(R509::Config)
                raise R509Error, "config must be a kind of R509::Config"
            end
        end

        # Signs a CSR
        # @option options :csr [String, R509::Csr, OpenSSL:X509::Request]
        # @option options :profile_name [String] The CA profile you want to use (eg "server in your config)
        # @option options :subject [Array] subject array to overwrite what's in the CSR
        # @option options :domains [Array] list of SAN names to add to the certificate's subjectAltName
        # @option options :message_digest [String] the message digest to use for this certificate instead of the config's default
        # @option options :serial [String] the serial number you want to issue the certificate with
        # @option options :not_before [Time] the notBefore for the certificate
        # @option options :not_after [Time] the notAfter for the certificate
        # @return [R509::Cert] the signed cert object
        def sign_cert(options)
            req = OpenSSL::X509::Request.new options[:csr]
            if !req.verify(req.public_key)
                raise R509Error, "Certificate request signature is invalid."
            end

            if options.has_key?(:message_digest)
                message_digest = R509::MessageDigest.new(options[:message_digest])
            else
                message_digest = R509::MessageDigest.new(@config.message_digest)
            end

            profile = @config.profile(options[:profile_name])

            san_names = merge_san_domains(req, options[:domains])

            #load ca key and cert
            ca_cert = @config.ca_cert
            ca_key = @config.ca_key

            if options.has_key?(:serial)
                serial = OpenSSL::BN.new(options[:serial].to_s)
            else
                #generate random serial in accordance with best practices
                #guidelines state 20-bits of entropy, but we can cram more in
                #per rfc5280 conforming CAs can make the serial field up to 20 octets
                serial = OpenSSL::BN.rand(160,0) # 160 bits is 20 bytes (octets).
                #since second param is 0 the most significant bit must always be 1
                #this theoretically gives us 159 bits of entropy
            end

            if options.has_key?(:not_before)
                not_before = options[:not_before]
            else
                #not_before will be set to 6 hours before now to prevent issues with bad system clocks (clients don't sync)
                not_before = Time.now - 6 * 60 * 60
            end
            if options.has_key?(:not_after)
                not_after = options[:not_after]
            else
                not_after = not_before + 365 * 24 * 60 * 60
            end

            cert = OpenSSL::X509::Certificate.new
            if(options[:subject].kind_of?(Array)) then
                name = OpenSSL::X509::Name.new options[:subject]
                cert.subject = name
            else
                cert.subject = req.subject
            end
            cert.issuer = ca_cert.subject
            cert.not_before = not_before
            cert.not_after = not_after
            cert.public_key = req.public_key
            cert.serial =serial
            cert.version = 2 #2 means v3


            basic_constraints = profile.basic_constraints
            key_usage = profile.key_usage
            extended_key_usage = profile.extended_key_usage
            certificate_policies = profile.certificate_policies
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
            conf = build_conf('certPolicies',profile.certificate_policies)
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
            cert.sign ca_key, message_digest.digest
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

        def parse_domains_from_csr(req)
            attributes = parse_attributes_from_csr(req) #method from CsrHelper module
            if attributes['subjectAltName'].kind_of?(Array)
                attributes['subjectAltName'].collect{ |domain| 'DNS:'+domain }
            else
                []
            end
        end

        def build_conf(section,data)
            conf = ["[#{section}]"]
            conf.concat data
            conf.join "\n"
        end

    end
end
