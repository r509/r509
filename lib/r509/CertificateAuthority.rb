require 'openssl'
require 'r509/Config'
require 'r509/Cert'
require 'r509/Exceptions'

# CertificateAuthority related classes
module R509::CertificateAuthority
    # Contains the certification authority signing operation methods
    class Signer
        # @param [R509::Config] @config
        def initialize(config=nil)
            @config = config

            if not @config.nil? and not @config.kind_of?(R509::Config::CaConfig)
                raise R509::R509Error, "config must be a kind of R509::Config::CaConfig or nil (for self-sign only)"
            end
            if not @config.nil? and @config.num_profiles == 0
                raise R509::R509Error, "You must have at least one CaProfile on your CaConfig to issue"
            end
        end

        # Signs a CSR
        # @option options :csr [R509::Csr]
        # @option options :spki [R509::Spki]
        # @option options :profile_name [String] The CA profile you want to use (eg "server in your config)
        # @option options :data_hash [Hash] a hash containing the subject and SAN names you want encoded for this cert. Generate by calling Csr#to_hash or Spki#to_hash
        # @option options :message_digest [String] the message digest to use for this certificate instead of the config's default
        # @option options :serial [String] the serial number you want to issue the certificate with
        # @option options :not_before [Time] the notBefore for the certificate
        # @option options :not_after [Time] the notAfter for the certificate
        # @return [R509::Cert] the signed cert object
        def sign(options)
            if @config.nil?
                raise R509::R509Error, "When instantiating the signer without a config you can only call #selfsign"
            end
            if options.has_key?(:csr) and options.has_key?(:spki)
                raise ArgumentError, "You can't pass both :csr and :spki"
            elsif not options.has_key?(:csr) and not options.has_key?(:spki)
                raise ArgumentError, "You must supply either :csr or :spki"
            elsif options.has_key?(:csr)
                if not options[:csr].kind_of?(R509::Csr)
                    raise ArgumentError, "You must pass an R509::Csr object for :csr"
                else
                    signable_object = options[:csr]
                end
            elsif not options.has_key?(:csr) and options.has_key?(:spki)
                if not options[:spki].kind_of?(R509::Spki)
                    raise ArgumentError, "You must pass an R509::Spki object for :spki"
                else
                    signable_object = options[:spki]
                end
            end

            if options.has_key?(:data_hash)
                san_names = options[:data_hash][:san_names]
                subject = options[:data_hash][:subject]
            else
                san_names = signable_object.to_hash[:san_names]
                subject = signable_object.to_hash[:subject]
            end



            if options.has_key?(:csr) and not options[:csr].verify_signature
                raise R509::R509Error, "Certificate request signature is invalid."
            end

            #handle DSA here
            if options.has_key?(:message_digest)
                message_digest = R509::MessageDigest.new(options[:message_digest])
            else
                message_digest = R509::MessageDigest.new(@config.message_digest)
            end

            profile = @config.profile(options[:profile_name])

            validated_subject = validate_subject(subject,profile)

            cert = build_cert(
                :subject => validated_subject.name,
                :issuer => @config.ca_cert.subject,
                :not_before => options[:not_before],
                :not_after => options[:not_after],
                :public_key => signable_object.public_key,
                :serial => options[:serial]
            )

            basic_constraints = profile.basic_constraints
            key_usage = profile.key_usage
            extended_key_usage = profile.extended_key_usage
            certificate_policies = profile.certificate_policies

            build_extensions(
                :subject_certificate => cert,
                :issuer_certificate => @config.ca_cert.cert,
                :basic_constraints => basic_constraints,
                :key_usage => key_usage,
                :extended_key_usage => extended_key_usage,
                :certificate_policies => certificate_policies,
                :san_names => san_names
            )


            #@config.ca_cert.key.key ... ugly. ca_cert returns R509::Cert
            # #key returns R509::PrivateKey and #key on that returns OpenSSL object we need
            cert.sign( @config.ca_cert.key.key, message_digest.digest )
            R509::Cert.new(:cert => cert)
        end

        # Self-signs a CSR
        # @option options :csr [R509::Csr]
        # @option options :message_digest [String] the message digest to use for this certificate (defaults to sha1)
        # @option options :serial [String] the serial number you want to issue the certificate with (defaults to random)
        # @option options :not_before [Time] the notBefore for the certificate (defaults to now)
        # @option options :not_after [Time] the notAfter for the certificate (defaults to 1 year)
        # @option options :san_names [Array] Optional array of subject alternative names
        # @return [R509::Cert] the signed cert object
        def selfsign(options)
            if not options.kind_of?(Hash)
                raise ArgumentError, "You must pass a hash of options consisting of at minimum :csr"
            end
            csr = options[:csr]
            if csr.key.nil?
                raise ArgumentError, 'CSR must also have a private key to self sign'
            end
            cert = build_cert(
                :subject => csr.subject.name,
                :issuer => csr.subject.name,
                :not_before => options[:not_before],
                :not_after => options[:not_after],
                :public_key => csr.public_key,
                :serial => options[:serial]
            )

            if options.has_key?(:san_names)
                san_names = options[:san_names]
            else
                san_names = csr.san_names
            end

            build_extensions(
                :subject_certificate => cert,
                :issuer_certificate => cert,
                :basic_constraints => "CA:TRUE",
                :san_names => san_names
            )


            if options.has_key?(:message_digest)
                message_digest = R509::MessageDigest.new(options[:message_digest])
            else
                message_digest = R509::MessageDigest.new('sha1')
            end

            # Csr#key returns R509::PrivateKey and #key on that returns OpenSSL object we need
            cert.sign( csr.key.key, message_digest.digest )
            R509::Cert.new(:cert => cert)
        end

        private

        def process_san_names(domains)
            domains.map { |domain| 'DNS: '+domain }.join(",")
        end

        def build_conf(section,data)
            conf = ["[#{section}]"]
            conf.concat data
            conf.join "\n"
        end

        def validate_subject(subject,profile)
            if profile.subject_item_policy.nil? then
                subject
            else
                profile.subject_item_policy.validate_subject(subject)
            end
        end

        def build_cert(options)

            cert = OpenSSL::X509::Certificate.new

            cert.subject = options[:subject]
            cert.issuer = options[:issuer]
            cert.not_before = calculate_not_before(options[:not_before])
            cert.not_after = calculate_not_after(options[:not_after],cert.not_before)
            cert.public_key = options[:public_key]
            cert.serial = create_serial(options[:serial])
            cert.version = 2 #2 means v3
            cert
        end

        def create_serial(serial)
            if not serial.nil?
                serial = OpenSSL::BN.new(serial.to_s)
            else
                #generate random serial in accordance with best practices
                #guidelines state 20-bits of entropy, but we can cram more in
                #per rfc5280 conforming CAs can make the serial field up to 20 octets
                serial = OpenSSL::BN.rand(160,0) # 160 bits is 20 bytes (octets).
                #since second param is 0 the most significant bit must always be 1
                #this theoretically gives us 159 bits of entropy
            end
            serial
        end

        def build_extensions(options)
            ef = OpenSSL::X509::ExtensionFactory.new

            ef.subject_certificate = options[:subject_certificate]

            ef.issuer_certificate = options[:issuer_certificate]

            ext = []
            if not options[:basic_constraints].nil?
                ext << ef.create_extension("basicConstraints", options[:basic_constraints], true)
            end
            if options.has_key?(:key_usage) and not options[:key_usage].empty?
                ext << ef.create_extension("keyUsage", options[:key_usage].join(","))
            end
            if options.has_key?(:extended_key_usage) and not options[:extended_key_usage].empty?
                ext << ef.create_extension("extendedKeyUsage", options[:extended_key_usage].join(","))
            end
            ext << ef.create_extension("subjectKeyIdentifier", "hash")

            #attach the key identifier if it's not a self-sign
            if not ef.subject_certificate == ef.issuer_certificate and R509::Cert.new(:cert=>options[:issuer_certificate]).extensions['subjectKeyIdentifier']
                ext << ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always")
            end

            if not options[:certificate_policies].nil? and not options[:certificate_policies].empty?
                conf = []
                conf_names = []
                i = 0
                options[:certificate_policies].each do |policy|
                    conf << build_conf("certPolicies#{i}",policy)
                    conf_names << "@certPolicies#{i}"
                    i+=1
                end
                ef.config = OpenSSL::Config.parse(conf.join("\n"))
                ext << ef.create_extension("certificatePolicies", conf_names.join(","))
            end
            #ef.config = OpenSSL::Config.parse(<<-_end_of_cnf_)
            #[certPolicies]
            #CPS.1 = http://www.example.com/cps
            #_end_of_cnf_

            if options.has_key?(:san_names) and not options[:san_names].empty?
                ext << ef.create_extension("subjectAltName", process_san_names(options[:san_names]))
            end

            if not @config.nil? and not @config.cdp_location.nil?
                ext << ef.create_extension("crlDistributionPoints", @config.cdp_location)
            end

            if not @config.nil? and not @config.ocsp_location.nil? then
            ext << ef.create_extension("authorityInfoAccess",
                        "OCSP;" << @config.ocsp_location)
            end
            options[:subject_certificate].extensions = ext
            nil
        end

        def calculate_not_before(not_before)
            if not_before.nil?
                #not_before will be set to 6 hours before now to prevent issues with bad system clocks (clients don't sync)
                not_before = Time.now - 6 * 60 * 60
            end
            not_before
        end

        def calculate_not_after(not_after,not_before)
            if not_after.nil?
                not_after = not_before + 365 * 24 * 60 * 60
            end
            not_after
        end

    end
end
