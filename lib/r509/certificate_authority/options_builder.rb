module R509::CertificateAuthority
  # A class to build hashes to send to the R509::CertificateAuthority::Signer. These are built from R509::Config::CertProfile objects and additional data supplied to the #build_and_enforce method.
  class OptionsBuilder
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
    # @option options :extensions [Array] An optional array of R509::Cert::Extensions::* objects. These will be merged with the extensions from the profile. If an extension in this array is also present in the profile, *the supplied extension will override the profile*.
    # @option options :not_before [Time] the notBefore for the certificate
    # @option options :not_after [Time] the notAfter for the certificate
    # @return [Hash] Hash of :message_digest, :subject, :extensions, and :csr/:spki ready to be passed to the Signer
    def build_and_enforce(options)
      profile = @config.profile(options[:profile_name])

      R509::CertificateAuthority::Signer.check_options(options)

      if (options.key?(:csr) and not options[:csr].verify_signature) or
         (options.key?(:spki) and not options[:spki].verify_signature)
        raise R509::R509Error, "Request signature is invalid."
      end

      raw_subject, public_key = R509::CertificateAuthority::Signer.extract_public_key_subject(options)

      message_digest = enforce_md(options[:message_digest],profile)
      subject = enforce_subject_item_policy(raw_subject,profile)
      enforce_not_after(options[:not_after])

      extensions = build_and_merge_extensions(options, profile, public_key)

      build_hash(subject, extensions, message_digest, options)
    end

    private

    def build_hash(subject, extensions, message_digest, options)
      return_hash = {
        :subject => subject,
        :extensions => extensions,
        :message_digest => message_digest,
      }
      return_hash[:csr] = options[:csr] unless options[:csr].nil?
      return_hash[:spki] = options[:spki] unless options[:spki].nil?
      return_hash[:not_before] = options[:not_before] unless options[:not_before].nil?
      return_hash[:not_after] = options[:not_after] unless options[:not_after].nil?
      return_hash
    end

    def enforce_not_after(not_after)
      if not not_after.nil? and @config.ca_cert.not_after < not_after
        raise R509::R509Error, 'The requested certificate lifetime would exceed the issuing CA.'
      end
    end

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

    def build_and_merge_extensions(options, profile, public_key)
      extensions = build_extensions(options,profile,public_key)

      if not options[:extensions].nil?
        extensions = merge_extensions(options,extensions)
      end
      extensions
    end

    def merge_extensions(options,extensions)
      ext_hash = {}
      extensions.each do |e|
        ext_hash[e.class] = e
      end
      options[:extensions].each do |e|
        ext_hash[e.class] = e
      end
      merged_ext = []
      ext_hash.each do |k,v|
        merged_ext.push(v)
      end
      return merged_ext
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

      extensions << profile.key_usage
      extensions << profile.extended_key_usage
      extensions << profile.certificate_policies
      extensions << profile.crl_distribution_points
      extensions << profile.authority_info_access
      extensions << profile.inhibit_any_policy
      extensions << profile.policy_constraints
      extensions << profile.name_constraints
      extensions << profile.ocsp_no_check
      extensions.compact
    end
  end
end
