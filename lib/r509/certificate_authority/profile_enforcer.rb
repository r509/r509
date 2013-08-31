module R509::CertificateAuthority
  # Provides enforcement of defined CertProfiles.
  class ProfileEnforcer
    def initialize(config)
      if not config.kind_of?(R509::Config::CAConfig)
        raise ArgumentError, "You must supply a R509::Config::CAConfig object to this class at instantiation"
      end
      @config = config
    end

    # @option options :profile_name [String] Name of profile to use
    # @option options :csr [R509::CSR]
    # @option options :spki [R509::SPKI]
    # @option options :subject [R509::Subject,OpenSSL::X509::Subject,Array] (optional for R509::CSR, required for R509::SPKI)
    # @option options :message_digest [String] the message digest to use for this certificate instead of the default (see R509::MessageDigest::DEFAULT_MD).
    # @option options :san_names [Array,R509::ASN1::GeneralNames] List of domains, IPs, email addresses, or URIs to encode as subjectAltNames. The type is determined from the structure of the strings via the R509::ASN1.general_name_parser method. You can also pass an explicit R509::ASN1::GeneralNames object
    # @return [Hash] Hash of enforced :message_digest, :subject, :extensions, and :csr/:spki
    def enforce(options)
      profile = @config.profile(options[:profile_name])

      R509::CertificateAuthority::Signer.check_options(options)

      if (options.has_key?(:csr) and not options[:csr].verify_signature) or
         (options.has_key?(:spki) and not options[:spki].verify_signature)
        raise R509::R509Error, "Request signature is invalid."
      end

      raw_subject, public_key = R509::CertificateAuthority::Signer.extract_public_key_subject(options)

      message_digest = enforce_md(options[:message_digest],profile)

      extensions = build_extensions(options,profile,public_key)

      subject = enforce_subject_item_policy(raw_subject,profile)

      return_hash = {
        :subject => subject,
        :extensions => extensions,
        :message_digest => message_digest,
      }
      return_hash[:csr] = options[:csr] unless options[:csr].nil?
      return_hash[:spki] = options[:spki] unless options[:spki].nil?
      return_hash
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

      extensions << profile.basic_constraints unless profile.basic_constraints.nil?

      extensions << R509::Cert::Extensions::SubjectKeyIdentifier.new(
        :public_key => public_key
      )

      extensions << R509::Cert::Extensions::AuthorityKeyIdentifier.new(
        :public_key => @config.ca_cert.public_key,
        :issuer_subject => @config.ca_cert.subject
      )

      extensions << profile.key_usage unless profile.key_usage.nil?

      extensions << profile.extended_key_usage unless profile.extended_key_usage.nil?

      extensions << profile.certificate_policies unless profile.certificate_policies.nil?

      extensions << profile.crl_distribution_points unless profile.crl_distribution_points.nil?

      extensions << profile.authority_info_access unless profile.authority_info_access.nil?

      extensions << profile.inhibit_any_policy unless profile.inhibit_any_policy.nil?

      extensions << profile.policy_constraints unless profile.policy_constraints.nil?

      extensions << profile.name_constraints unless profile.name_constraints.nil?

      extensions << profile.ocsp_no_check unless profile.ocsp_no_check.nil?

      if present?(options[:san_names])
        gns = R509::ASN1.general_name_parser(options[:san_names])
        extensions << R509::Cert::Extensions::SubjectAlternativeName.new(:value => gns)
      end

      extensions
    end

    # check if an object exists and is not empty
    def present?(obj)
      (not obj.nil? and not obj.empty?)
    end

  end
end
