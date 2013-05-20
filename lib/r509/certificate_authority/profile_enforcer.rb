module R509::CertificateAuthority
  # Provides enforcement of defined CertProfiles.
  class ProfileEnforcer
    def initialize(config)
      if not config.kind_of?(R509::Config::CAConfig)
        raise ArgumentError, "You must supply a R509::Config::CAConfig object to this class at instantiation"
      end
      @config = config
    end

    # @param [Hash] options Options hash
    # @param [String] profile Name of profile to use
    # @return [Hash] Hash of enforced md, subject, and extensions
    def enforce(options,profile)
      profile = @config.profile(profile)

      if options.has_key?(:csr) and not options[:csr].verify_signature
        raise R509::R509Error, "Certificate request signature is invalid."
      end

      raw_subject, public_key = R509::CertificateAuthority::Signer.extract_public_key_subject(options)

      message_digest = enforce_md(options[:message_digest],profile)

      extensions = build_extensions(options,profile,public_key)

      subject = enforce_subject_item_policy(raw_subject,profile)

      {
        :subject => subject,
        :extensions => extensions,
        :message_digest => message_digest
      }
    end

    private

    def enforce_md(requested_md,profile)
      # prior to OpenSSL 1.0 DSA could only use DSS1 (aka SHA1) signatures. post-1.0 anything
      # goes but at the moment we don't enforce this restriction so an OpenSSL error could
      # bubble up if they do it wrong.
      #
      # First let's check to see if the config restricts the allowed mds
      if not profile.allowed_mds.nil? and not requested_md.nil?
        if profile.allowed_mds.include?(requested_md.upcase)
          message_digest = R509::MessageDigest.new(requested_md)
        else
          raise R509::R509Error, "The message digest passed is not allowed by this configuration. Allowed digests: #{profile.allowed_mds.join(", ")}"
        end
      else
        # it doesn't, so either use their md (if valid) or the default one
      message_digest = (not requested_md.nil?)? R509::MessageDigest.new(requested_md) : R509::MessageDigest.new(profile.default_md)
      end
      message_digest.name
    end

    # @return [R509::Subject]
    def enforce_subject_item_policy(subject,profile)
      if profile.subject_item_policy.nil? then
        subject
      else
        profile.subject_item_policy.validate_subject(subject)
      end
    end

    def build_extensions(options,profile,public_key)
      extensions = []

      if present?(profile.basic_constraints)
        extensions << R509::Cert::Extensions::BasicConstraints.new(profile.basic_constraints)
      end

      extensions << R509::Cert::Extensions::SubjectKeyIdentifier.new(
        :public_key => public_key
      )

      extensions << R509::Cert::Extensions::AuthorityKeyIdentifier.new(
        :issuer_certificate => @config.ca_cert
      )

      if present?(profile.key_usage)
        extensions << R509::Cert::Extensions::KeyUsage.new(profile.key_usage)
      end

      if present?(profile.extended_key_usage)
        extensions << R509::Cert::Extensions::ExtendedKeyUsage.new(profile.extended_key_usage)
      end

      if present?(profile.certificate_policies)
        extensions << R509::Cert::Extensions::CertificatePolicies.new(profile.certificate_policies)
      end

      if present?(profile.cdp_location)
        extensions << R509::Cert::Extensions::CRLDistributionPoints.new(profile.cdp_location)
      end

      if present?(profile.ocsp_location) or present?(profile.ca_issuers_location)
        extensions << R509::Cert::Extensions::AuthorityInfoAccess.new(
          :ocsp_location => profile.ocsp_location,
          :ca_issuers_location => profile.ca_issuers_location
        )
      end

      if profile.inhibit_any_policy
        extensions << R509::Cert::Extensions::InhibitAnyPolicy.new(profile.inhibit_any_policy)
      end

      if present?(profile.policy_constraints)
        extensions << R509::Cert::Extensions::PolicyConstraints.new(profile.policy_constraints)
      end

      if present?(profile.name_constraints)
        extensions << R509::Cert::Extensions::NameConstraints.new(profile.name_constraints)
      end

      if profile.ocsp_no_check
        extensions << R509::Cert::Extensions::OCSPNoCheck.new(profile.ocsp_no_check)
      end
      if present?(options[:san_names])
        extensions << R509::Cert::Extensions::SubjectAlternativeName.new(options[:san_names])
      end

      extensions
    end

    # check if an object exists and is not empty
    def present?(obj)
      (not obj.nil? and not obj.empty?)
    end

  end
end
