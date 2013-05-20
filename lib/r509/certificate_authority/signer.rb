require 'openssl'
require 'r509/config'
require 'r509/cert'
require 'r509/exceptions'
require 'r509/ec-hack'

# CertificateAuthority related classes
module R509::CertificateAuthority
  # Contains the certification authority signing operation methods
  class Signer
    # @param [R509::Config] config
    def initialize(config=nil)
      @config = config

      if not @config.nil? and not @config.kind_of?(R509::Config::CAConfig)
        raise R509::R509Error, "config must be a kind of R509::Config::CAConfig or nil (for self-sign only)"
      end
      if not @config.nil? and not @config.ca_cert.has_private_key?
        raise R509::R509Error, "You must have a private key associated with your CA certificate to issue"
      end
    end

    # Signs a CSR
    # @option options :csr [R509::CSR]
    # @option options :spki [R509::SPKI]
    # @option options :profile_name [String] The CA profile you want to use (eg "server" in your config)
    # @option options :subject [R509::Subject,OpenSSL::X509::Subject,Array] (optional for R509::CSR, required for R509::SPKI)
    # @option options :san_names [Array,R509::ASN1::GeneralNames] optional either an array of names that will be automatically parsed to determine their type, or an explicit R509::ASN1::GeneralNames object
    # @option options :message_digest [String] the message digest to use for this certificate instead of the config's default. If you have an allowed_message_digests array in your config then the passed value will be checked to see if it is allowed.
    # @option options :serial [String] the serial number you want to issue the certificate with
    # @option options :not_before [Time] the notBefore for the certificate
    # @option options :not_after [Time] the notAfter for the certificate
    # @return [R509::Cert] the signed cert object
    def sign(options)
      if @config.nil?
        raise R509::R509Error, "When instantiating the signer without a config you can only call #selfsign"
      elsif @config.num_profiles == 0
        raise R509::R509Error, "You must have at least one CAProfile on your CAConfig to issue"
      end

      check_options(options)

      subject, san_names, public_key = extract_public_key_subject_san(options)


      if options.has_key?(:csr) and not options[:csr].verify_signature
        raise R509::R509Error, "Certificate request signature is invalid."
      end

      # prior to OpenSSL 1.0 DSA could only use DSS1 (aka SHA1) signatures. post-1.0 anything
      # goes but at the moment we don't enforce this restriction so an OpenSSL error could
      # bubble up if they do it wrong.
      #
      # First let's check to see if the config restricts the allowed mds
      if not @config.allowed_mds.nil? and not options[:message_digest].nil?
        if @config.allowed_mds.include?(options[:message_digest].upcase)
          message_digest = R509::MessageDigest.new(options[:message_digest])
        else
          raise R509::R509Error, "The message digest passed is not allowed by this configuration. Allowed digests: #{@config.allowed_mds.join(", ")}"
        end
      else
        # it doesn't, so either use their md (if valid) or the default one
        message_digest = (options.has_key?(:message_digest))? R509::MessageDigest.new(options[:message_digest]) : R509::MessageDigest.new(@config.default_md)
      end

      profile = @config.profile(options[:profile_name])

      validated_subject = validate_subject(subject,profile)

      cert = build_cert(
        :subject => validated_subject.name,
        :issuer => @config.ca_cert.subject.name,
        :not_before => options[:not_before],
        :not_after => options[:not_after],
        :public_key => public_key,
        :serial => options[:serial]
      )

      basic_constraints = profile.basic_constraints
      key_usage = profile.key_usage
      extended_key_usage = profile.extended_key_usage
      certificate_policies = profile.certificate_policies
      ocsp_no_check = profile.ocsp_no_check

      build_extensions(
        :subject_certificate => cert,
        :issuer_certificate => @config.ca_cert.cert,
        :basic_constraints => basic_constraints,
        :key_usage => key_usage,
        :extended_key_usage => extended_key_usage,
        :ocsp_no_check => ocsp_no_check,
        :certificate_policies => certificate_policies,
        :san_names => san_names,
        :inhibit_any_policy => profile.inhibit_any_policy,
        :policy_constraints => profile.policy_constraints,
        :name_constraints => profile.name_constraints
      )


      #@config.ca_cert.key.key ... ugly. ca_cert returns R509::Cert
      # #key returns R509::PrivateKey and #key on that returns OpenSSL object we need
      cert.sign( @config.ca_cert.key.key, message_digest.digest )
      R509::Cert.new(:cert => cert)
    end

    # Self-signs a CSR
    # @option options :csr [R509::CSR]
    # @option options :message_digest [String] the message digest to use for this certificate (defaults to sha1)
    # @option options :serial [String] the serial number you want to issue the certificate with (defaults to random)
    # @option options :not_before [Time] the notBefore for the certificate (defaults to now)
    # @option options :not_after [Time] the notAfter for the certificate (defaults to 1 year)
    # @option options :san_names [Array,R509::ASN1::GeneralNames] optional either an array of names that will be automatically parsed to determine their type, or an explicit R509::ASN1::GeneralNames object
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

      sans = (options.has_key?(:san_names))? options[:san_names] : csr.san
      san_names = parse_san_names(sans)

      build_extensions(
        :subject_certificate => cert,
        :issuer_certificate => cert,
        :basic_constraints => {"ca" => true },
        :san_names => san_names
      )


      if options.has_key?(:message_digest)
        message_digest = R509::MessageDigest.new(options[:message_digest])
      else
        message_digest = R509::MessageDigest.new('sha1')
      end

      # CSR#key returns R509::PrivateKey and #key on that returns OpenSSL object we need
      cert.sign( csr.key.key, message_digest.digest )
      R509::Cert.new(:cert => cert)
    end

    private

    def check_options(options)
      if options.has_key?(:csr) and options.has_key?(:spki)
        raise ArgumentError, "You can't pass both :csr and :spki"
      elsif not options.has_key?(:csr) and not options.has_key?(:spki)
        raise ArgumentError, "You must supply either :csr or :spki"
      elsif options.has_key?(:csr)
        if not options[:csr].kind_of?(R509::CSR)
          raise ArgumentError, "You must pass an R509::CSR object for :csr"
        end
      elsif not options.has_key?(:csr) and options.has_key?(:spki)
        if not options[:spki].kind_of?(R509::SPKI)
          raise ArgumentError, "You must pass an R509::SPKI object for :spki"
        end
      end
    end

    def extract_public_key_subject_san(options)
      if options.has_key?(:csr)
        subject = (options.has_key?(:subject))? R509::Subject.new(options[:subject]) : options[:csr].subject
        sans = (options.has_key?(:san_names))? options[:san_names] : options[:csr].san
        san_names = parse_san_names(sans)
        public_key = options[:csr].public_key
      else
        # spki
        if not options.has_key?(:subject)
          raise ArgumentError, "You must supply :subject when passing :spki"
        end
        public_key = options[:spki].public_key
        subject = R509::Subject.new(options[:subject])
        san_names = parse_san_names(options[:san_names]) # optional
      end

      [subject,san_names,public_key]
    end

    def parse_san_names(sans)
      case sans
      when nil then nil
      when R509::ASN1::GeneralNames then sans
      when Array then R509::ASN1.general_name_parser(sans)
      else
        raise ArgumentError, "When passing SAN names it must be provided as either an array of strings or an R509::ASN1::GeneralNames object"
      end
    end

    def build_conf(section,hash,index)
      conf = ["[#{section}]"]
      conf.push "policyIdentifier=#{hash["policy_identifier"]}" unless hash["policy_identifier"].nil?
      hash["cps_uris"].each_with_index do |cps,idx|
        conf.push "CPS.#{idx+1}=\"#{cps}\""
      end if hash["cps_uris"].respond_to?(:each_with_index)

      user_notice_confs = []
      hash["user_notices"].each_with_index do |un,k|
        conf.push "userNotice.#{k+1}=@user_notice#{k+1}#{index}"
        user_notice_confs.push "[user_notice#{k+1}#{index}]"
        user_notice_confs.push "explicitText=\"#{un["explicit_text"]}\"" unless un["explicit_text"].nil?
        # if org is supplied notice numbers is also required (and vice versa). enforced in CAProfile
        user_notice_confs.push "organization=\"#{un["organization"]}\"" unless un["organization"].nil?
        user_notice_confs.push "noticeNumbers=\"#{un["notice_numbers"]}\"" unless un["notice_numbers"].nil?
      end unless not hash["user_notices"].kind_of?(Array)

      conf.concat(user_notice_confs)
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
        # generate random serial in accordance with best practices
        # guidelines state 20-bits of entropy, but we can cram more in
        # per rfc5280 conforming CAs can make the serial field up to 20 octets
        # to prevent even the incredibly remote possibility of collision we'll
        # concatenate current time (to the microsecond) with a random num
        rand = OpenSSL::BN.rand(96,0) # 96 bits is 12 bytes (octets).
        serial = OpenSSL::BN.new((Time.now.to_f*1000000).to_i.to_s + rand.to_s)
        # since second param is 0 the most significant bit must always be 1
        # this theoretically gives us 95 bits of entropy + microtime, which
        # adds a non-zero quantity of entropy. depending upon how predictable
        # your issuance is, this could range from a reasonably large quantity
        # of entropy to very little
      end
      serial
    end

    def build_extensions(options)
      ef = OpenSSL::X509::ExtensionFactory.new

      ef.subject_certificate = options[:subject_certificate]

      ef.issuer_certificate = options[:issuer_certificate]

      ext = []
      if not options[:basic_constraints].nil?
        bc = options[:basic_constraints]
        if bc["ca"] == true
          bc_value = "CA:TRUE"
          if not bc["path_length"].nil?
            bc_value += ",pathlen:#{bc["path_length"]}"
          end
        else
          bc_value = "CA:FALSE"
        end

        ext << ef.create_extension("basicConstraints", bc_value, true)
      end
      if not options[:key_usage].nil? and not options[:key_usage].empty?
        ext << ef.create_extension("keyUsage", options[:key_usage].join(","))
      end
      if not options[:extended_key_usage].nil? and not options[:extended_key_usage].empty?
        ext << ef.create_extension("extendedKeyUsage", options[:extended_key_usage].join(","))
      end
      ext << ef.create_extension("subjectKeyIdentifier", "hash")

      #attach the key identifier if it's not a self-sign
      if not ef.subject_certificate == ef.issuer_certificate and not R509::Cert.new(:cert=>options[:issuer_certificate]).authority_key_identifier.nil?
        ext << ef.create_extension("authorityKeyIdentifier", "keyid:always") # this could also be keyid:always,issuer:always
      end

      if not options[:certificate_policies].nil? and options[:certificate_policies].respond_to?(:each)
        conf = []
        policy_names = ["ia5org"]
        options[:certificate_policies].each_with_index do |policy,i|
          conf << build_conf("certPolicies#{i}",policy,i)
          policy_names << "@certPolicies#{i}"
        end
        ef.config = OpenSSL::Config.parse(conf.join("\n"))
        ext << ef.create_extension("certificatePolicies", policy_names.join(","))
      end

      if not options[:san_names].nil? and not options[:san_names].names.empty?
        serialize = options[:san_names].serialize_names
        ef.config = OpenSSL::Config.parse(serialize[:conf])
        ext << ef.create_extension("subjectAltName", serialize[:extension_string])
      end

      if not @config.nil? and not @config.cdp_location.nil? and not @config.cdp_location.empty?
        gns = R509::ASN1.general_name_parser(@config.cdp_location)
        serialize = gns.serialize_names
        ef.config = OpenSSL::Config.parse(serialize[:conf])
        ext << ef.create_extension("crlDistributionPoints", serialize[:extension_string])
      end

      #authorityInfoAccess processing
      if not @config.nil?
        aia = []
        aia_conf = []

        if not @config.ocsp_location.nil? and not @config.ocsp_location.empty?
          gns = R509::ASN1.general_name_parser(@config.ocsp_location)
          gns.names.each do |ocsp|
            serialize = ocsp.serialize_name
            aia.push "OCSP;#{serialize[:extension_string]}"
            aia_conf.push serialize[:conf]
          end
        end

        if not @config.nil? and not @config.ca_issuers_location.nil? and not @config.ca_issuers_location.empty?
          gns = R509::ASN1.general_name_parser(@config.ca_issuers_location)
          gns.names.each do |ca_issuers|
            serialize = ca_issuers.serialize_name
            aia.push "caIssuers;#{serialize[:extension_string]}"
            aia_conf.push serialize[:conf]
          end
        end

        if not aia.empty?
          ef.config = OpenSSL::Config.parse(aia_conf.join("\n"))
          ext << ef.create_extension("authorityInfoAccess",aia.join(","))
        end
      end

      if options[:inhibit_any_policy]
        ext << ef.create_extension("inhibitAnyPolicy",options[:inhibit_any_policy].to_s,true) # must be set critical per RFC 5280
      end

      if options[:policy_constraints]
        pc = options[:policy_constraints]
        constraints = []
        constraints << "requireExplicitPolicy:#{pc["require_explicit_policy"]}" unless pc["require_explicit_policy"].nil?
        constraints << "inhibitPolicyMapping:#{pc["inhibit_policy_mapping"]}" unless pc["inhibit_policy_mapping"].nil?
        ext << ef.create_extension("policyConstraints",constraints.join(","),true) # must be set critical per RFC 5280
      end

      if options[:name_constraints]
        nc = options[:name_constraints]
        nc_data = []
        nc_conf = []
        if not nc["permitted"].nil?
          gns = R509::ASN1::GeneralNames.new
          nc["permitted"].each do |p|
            gns.create_item(:type => p["type"], :value => p["value"])
          end
          gns.names.each do |permitted|
            serialize = permitted.serialize_name
            nc_data.push "permitted;#{serialize[:extension_string]}"
            nc_conf.push serialize[:conf]
          end
        end
        if not nc["excluded"].nil?
          gns = R509::ASN1::GeneralNames.new
          nc["excluded"].each do |p|
            gns.create_item(:type => p["type"], :value => p["value"])
          end
          gns.names.each do |excluded|
            serialize = excluded.serialize_name
            nc_data.push "excluded;#{serialize[:extension_string]}"
            nc_conf.push serialize[:conf]
          end
        end

        ef.config = OpenSSL::Config.parse nc_conf.join("\n")
        ext << ef.create_extension("nameConstraints",nc_data.join(","))
      end

      if options[:ocsp_no_check]
        # the value of this extension is not encoded. presence is all that matters
        ext << ef.create_extension("noCheck","yes")
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
