require 'openssl'
require 'r509/exceptions'
require 'r509/io_helpers'
require 'r509/helpers'
require 'r509/cert/extensions'

module R509
  # The primary certificate object.
  class Cert
    include R509::IOHelpers
    include R509::Helpers

    attr_reader :cert, :key, :subject, :issuer

    # @option opts [String,OpenSSL::X509::Certificate] :cert a cert
    # @option opts [R509::PrivateKey,String] :key optional private key to supply. either an unencrypted PEM/DER string or an R509::PrivateKey object (use the latter if you need password/hardware support)
    # @option opts [String] :pkcs12 a PKCS12 object containing both key and cert
    # @option opts [String] :password password for PKCS12 or private key (if supplied)
    def initialize(opts = {})
      unless opts.kind_of?(Hash)
        raise ArgumentError, 'Must provide a hash of options'
      end
      if opts.key?(:pkcs12) and ( opts.key?(:key) or opts.key?(:cert))
        raise ArgumentError, "When providing pkcs12, do not pass cert or key"
      elsif opts.key?(:pkcs12)
        pkcs12 = OpenSSL::PKCS12.new(opts[:pkcs12], opts[:password])
        parse_certificate(pkcs12.certificate)
        parse_private_key(pkcs12.key)
      elsif !opts.key?(:cert)
        raise ArgumentError, 'Must provide :cert or :pkcs12'
      else
        csr_check(opts[:cert])
        parse_certificate(opts[:cert])
      end

      if opts.key?(:key)
        parse_private_key(opts[:key], opts[:password])
      end
    end

    # Helper method to quickly load a cert from the filesystem
    #
    # @param [String] filename Path to file you want to load
    # @return [R509::Cert] cert object
    def self.load_from_file(filename)
      R509::Cert.new(:cert => IOHelpers.read_data(filename))
    end

    alias_method :to_s, :to_pem

    # Returns beginning (notBefore) of certificate validity period
    #
    # @return [Time] time object
    def not_before
      @cert.not_before
    end

    # Returns the serial number of the certificate in decimal form
    #
    # @return [Integer]
    def serial
      @cert.serial.to_i
    end

    # Returns the serial number of the certificate in hexadecimal form
    #
    # @return [String]
    def hexserial
      @cert.serial.to_s(16)
    end

    # Returns ending (notAfter) of certificate validity period
    #
    # @return [Time] time object
    def not_after
      @cert.not_after
    end

    # Returns the certificate public key
    #
    # @return [OpenSSL::PKey::RSA] public key object
    def public_key
      @cert.public_key
    end

    # Returns the certificate fingerprint with the specified algorithm (default sha1)
    #
    # @param [String] algorithm Which algorithm to use for the fingerprint. See R509::MessageDigest for supported algorithm names
    # @return [String] hex digest of the certificate
    def fingerprint(algorithm = 'sha1')
      message_digest = R509::MessageDigest.new(algorithm)
      md = message_digest.digest
      md.update(@cert.to_der)
      md.to_s
    end

    # Returns whether the current time is between the notBefore and notAfter times in
    # the certificate.
    #
    # @return [Boolean]
    def valid?
      valid_at?(Time.now)
    end

    # Returns whether the certificate was between its notBefore and notAfter at the time provided
    #
    # @param [Time,Integer] time Time object or integer timestamp
    # @return [Boolean]
    def valid_at?(time)
      if time.kind_of?(Integer)
        time = Time.at(time)
      end

      if (self.not_after < time) or (self.not_before > time)
        false
      else
        true
      end
    end

    # @return [Boolean] Boolean of whether the object contains a private key
    def has_private_key?
      !@key.nil?
    end

    # Return the CN, as well as all the subject alternative names (SANs).
    #
    # @return [Array] the array of names. Returns an empty array if
    #  there are no names, at all. Discards SAN types
    def all_names
      ret = []
      ret << @subject.CN unless @subject.CN.nil?
      ret.concat(self.san.names.map { |n| n.value }) unless self.san.nil?

      ret.sort.uniq
    end

    # Returns signature algorithm
    #
    # @return [String] value of the signature algorithm. E.g. sha1WithRSAEncryption, sha256WithRSAEncryption, md5WithRSAEncryption, et cetera
    def signature_algorithm
      @cert.signature_algorithm
    end

    # Writes cert and key into PKCS12 format using OpenSSL defaults for encryption (des3)
    # @param [String, #write] filename_or_io Either a string of the path for
    #  the file that you'd like to write, or an IO-like object.
    # @param [String] password password
    # @param [String] friendly_name An optional string to encode in the PKCS12 for friendlyName. defaults to "r509 pkcs12"
    def write_pkcs12(filename_or_io, password, friendly_name = 'r509 pkcs12')
      if @key.nil?
        raise R509::R509Error, "Writing a PKCS12 requires both key and cert"
      end
      pkcs12 = OpenSSL::PKCS12.create(password, friendly_name, @key.key, @cert)
      write_data(filename_or_io, pkcs12.to_der)
    end

    # Checks the given CRL for this certificate's serial number. Note that this does NOT
    # check to verify that the CRL you're checking is signed by the same CA as the cert
    # so do that check yourself
    #
    # @param [R509::CRL::SignedList] r509_crl A CRL from the CA that issued this certificate.
    def is_revoked_by_crl?(r509_crl)
      r509_crl.revoked?(self.serial)
    end

    # Returns the certificate extensions as a hash of R509::Cert::Extensions
    # specific objects.
    #
    # @return [Hash] A hash, in which the values are classes from the
    # R509::Cert::Extensions module, each specific to the extension. The hash
    # is keyed with the R509 extension class. Extensions without an R509
    # implementation are ignored (see #get_unknown_extensions).
    def extensions
      if @r509_extensions.nil?
        @r509_extensions = Extensions.wrap_openssl_extensions(self.cert.extensions)
      end

      @r509_extensions
    end

    # Returns an array of OpenSSL::X509::Extension objects representing the
    # extensions that do not have R509 implementations.
    #
    # @return [Array] An array of OpenSSL::X509::Extension objects.
    def unknown_extensions
      Extensions.get_unknown_extensions(self.cert.extensions)
    end

    #
    # Shortcuts to extensions
    #

    # Returns this object's BasicConstraints extension as an R509 extension
    #
    # @return [R509::Cert::Extensions::BasicConstraints] The object, or nil
    # if this cert does not have a BasicConstraints extension.
    def basic_constraints
      extensions[R509::Cert::Extensions::BasicConstraints]
    end

    # Returns this object's KeyUsage extension as an R509 extension
    #
    # @return [R509::Cert::Extensions::KeyUsage] The object, or nil
    # if this cert does not have a KeyUsage extension.
    def key_usage
      extensions[R509::Cert::Extensions::KeyUsage]
    end
    alias_method :ku, :key_usage

    # Returns this object's ExtendedKeyUsage extension as an R509 extension
    #
    # @return [R509::Cert::Extensions::ExtendedKeyUsage] The object, or nil
    # if this cert does not have a ExtendedKeyUsage extension.
    def extended_key_usage
      extensions[R509::Cert::Extensions::ExtendedKeyUsage]
    end
    alias_method :eku, :extended_key_usage

    # Returns this object's SubjectKeyIdentifier extension as an R509 extension
    #
    # @return [R509::Cert::Extensions::SubjectKeyIdentifier] The object, or nil
    # if this cert does not have a SubjectKeyIdentifier extension.
    def subject_key_identifier
      extensions[R509::Cert::Extensions::SubjectKeyIdentifier]
    end

    # Returns this object's AuthorityKeyIdentifier extension as an R509 extension
    #
    # @return [R509::Cert::Extensions::AuthorityKeyIdentifier] The object, or nil
    # if this cert does not have a AuthorityKeyIdentifier extension.
    def authority_key_identifier
      extensions[R509::Cert::Extensions::AuthorityKeyIdentifier]
    end

    # Returns this object's SubjectAlternativeName extension as an R509 extension
    #
    # @return [R509::Cert::Extensions::SubjectAlternativeName] The object, or nil
    # if this cert does not have a SubjectAlternativeName extension.
    def subject_alternative_name
      extensions[R509::Cert::Extensions::SubjectAlternativeName]
    end
    alias_method :san, :subject_alternative_name
    alias_method :subject_alt_name, :subject_alternative_name

    # Returns this object's AuthorityInfoAccess extension as an R509 extension
    #
    # @return [R509::Cert::Extensions::AuthorityInfoAccess] The object, or nil
    # if this cert does not have a AuthorityInfoAccess extension.
    def authority_info_access
      extensions[R509::Cert::Extensions::AuthorityInfoAccess]
    end
    alias_method :aia, :authority_info_access

    # Returns this object's CRLDistributionPoints extension as an R509 extension
    #
    # @return [R509::Cert::Extensions::CRLDistributionPoints] The object, or nil
    # if this cert does not have a CRLDistributionPoints extension.
    def crl_distribution_points
      extensions[R509::Cert::Extensions::CRLDistributionPoints]
    end
    alias_method :cdp, :crl_distribution_points

    # Returns true if the OCSP No Check extension is present
    # (value is irrelevant to this extension)
    #
    # @return [Boolean] presence/absence of the nocheck extension
    def ocsp_no_check?
      (extensions.key?(R509::Cert::Extensions::OCSPNoCheck))
    end

    # Returns this object's CertificatePolicies extension as an R509 extension
    #
    # @return [R509::Cert::Extensions::CertificatePolicies] The object, or nil
    # if this cert does not have a CertificatePolicies extension.
    def certificate_policies
      extensions[R509::Cert::Extensions::CertificatePolicies]
    end

    # Returns this object's InhibitAnyPolicy extension as an R509 extension
    #
    # @return [R509::Cert::Extensions::InhibitAnyPolicy] The object, or nil
    # if this cert does not have a InhibitAnyPolicy extension.
    def inhibit_any_policy
      extensions[R509::Cert::Extensions::InhibitAnyPolicy]
    end

    # Returns this object's PolicyConstraints extension as an R509 extension
    #
    # @return [R509::Cert::Extensions::PolicyConstraints] The object, or nil
    # if this cert does not have a PolicyConstraints extension.
    def policy_constraints
      extensions[R509::Cert::Extensions::PolicyConstraints]
    end

    # Returns this object's NameConstraints extension as an R509 extension
    #
    # @return [R509::Cert::Extensions::NameConstraints] The object, or nil
    # if this cert does not have a NameConstraints extension.
    def name_constraints
      extensions[R509::Cert::Extensions::NameConstraints]
    end

    private

    # This method exists only to provide a friendlier error msg if you attempt to
    # parse a CSR as a certificate. All for Sean
    def csr_check(cert)
      begin
        OpenSSL::X509::Request.new cert
        raise ArgumentError, 'Cert provided is actually a certificate signing request.'
      rescue OpenSSL::X509::RequestError
        # do nothing, it shouldn't be a CSR anyway!
      end
    end

    def parse_certificate(cert)
      @cert = OpenSSL::X509::Certificate.new cert
      @subject = R509::Subject.new(@cert.subject)
      @issuer = R509::Subject.new(@cert.issuer)
    end

    def parse_private_key(key, password = nil)
      unless key.kind_of?(R509::PrivateKey)
        key = R509::PrivateKey.new(:key => key, :password => password)
      end
      unless @cert.public_key.to_der == key.public_key.to_der
        raise R509Error, 'Key does not match cert.'
      end
      @key = key
    end

    # Returns the proper instance variable
    alias_method :internal_obj, :cert
  end
end
