require 'openssl'
require 'r509/exceptions'
require 'r509/io_helpers'
require 'r509/cert/extensions'

module R509
  # The primary certificate object.
  class Cert
  include R509::IOHelpers

    attr_reader :cert, :key

    # @option opts [String,OpenSSL::X509::Certificate] :cert a cert
    # @option opts [R509::PrivateKey,String] :key optional private key to supply. either an unencrypted PEM/DER string or an R509::PrivateKey object (use the latter if you need password/hardware support)
    # @option opts [String] :pkcs12 a PKCS12 object containing both key and cert
    # @option opts [String] :password password for PKCS12 or private key (if supplied)
    def initialize(opts={})
      if not opts.kind_of?(Hash)
        raise ArgumentError, 'Must provide a hash of options'
      end
      if opts.has_key?(:pkcs12) and ( opts.has_key?(:key) or opts.has_key?(:cert) )
        raise ArgumentError, "When providing pkcs12, do not pass cert or key"
      elsif opts.has_key?(:pkcs12)
        pkcs12 = OpenSSL::PKCS12.new( opts[:pkcs12], opts[:password] )
        parse_certificate(pkcs12.certificate)
        key = R509::PrivateKey.new( :key => pkcs12.key )
      elsif not opts.has_key?(:cert)
        raise ArgumentError, 'Must provide :cert or :pkcs12'
      else
        csr_check(opts[:cert])
        parse_certificate(opts[:cert])
      end

      if opts.has_key?(:key)
        if opts[:key].kind_of?(R509::PrivateKey)
          key = opts[:key]
        else
          key = R509::PrivateKey.new( :key => opts[:key], :password => opts[:password] )
        end
      end
      associate_private_key(key)
    end

    # Helper method to quickly load a cert from the filesystem
    #
    # @param [String] filename Path to file you want to load
    # @return [R509::Cert] cert object
    def self.load_from_file( filename )
      return R509::Cert.new(:cert => IOHelpers.read_data(filename) )
    end


    # Converts the Cert into the PEM format
    #
    # @return [String] the Cert converted into PEM format.
    def to_pem
      if @cert.kind_of?(OpenSSL::X509::Certificate)
        return @cert.to_pem.chomp
      end
    end

    alias :to_s :to_pem

    # Converts the Cert into the DER format
    #
    # @return [String] the Cert converted into DER format.
    def to_der
      if @cert.kind_of?(OpenSSL::X509::Certificate)
        return @cert.to_der
      end
    end

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

    # Returns the issuer
    #
    # @return [OpenSSL::X509::Name] issuer object. Can be parsed as string easily
    def issuer
      @cert.issuer
    end

    # @return [String] The common name (CN) component of the issuer
    def issuer_cn
      return nil if self.issuer.nil?

      self.issuer.to_a.each do |part, value, length|
        return value if part.upcase == 'CN'
      end

      # return nil if we didn't find a CN part
      return nil
    end

    # Returns the certificate fingerprint with the specified algorithm (default sha1)
    #
    # @param [String] algorithm Which algorithm to use for the fingerprint. See R509::MessageDigest for supported algorithm names
    # @return [String] hex digest of the certificate
    def fingerprint(algorithm='sha1')
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

    # Returns the subject
    #
    # @return [OpenSSL::X509::Name] subject object. Can be parsed as string easily
    def subject
      @cert.subject
    end

    # @return [Boolean] Boolean of whether the object contains a private key
    def has_private_key?
      if not @key.nil?
        true
      else
        false
      end
    end

    # @return [Array] list of SAN DNS names
    def san_names
      if self.subject_alternative_name.nil?
        return []
      else
        return self.subject_alternative_name.dns_names
      end
    end

    # Returns the CN component, if any, of the subject
    #
    # @return [String]
    def subject_cn()
      return self.subject_component('CN')
    end

    # Returns subject component
    #
    # @return [String] value of the subject component requested
    def subject_component short_name
      match = @cert.subject.to_a.find { |x| x[0] == short_name }
      return nil if match.nil?
      return match[1]
    end

    # Return the CN, as well as all the subject alternative names (SANs).
    #
    # @return [Array] the array of names. Returns an empty array if
    #  there are no names, at all.
    def subject_names
      ret = []
      ret << subject_cn unless subject_cn.nil?
      ret.concat( self.san_names )

      return ret.sort.uniq
    end

    # Returns whether the public key is RSA
    #
    # @return [Boolean] true if the public key is RSA, false otherwise
    def rsa?
      @cert.public_key.kind_of?(OpenSSL::PKey::RSA)
    end

    # Returns whether the public key is DSA
    #
    # @return [Boolean] true if the public key is DSA, false otherwise
    def dsa?
      @cert.public_key.kind_of?(OpenSSL::PKey::DSA)
    end

    # Returns whether the public key is EC
    #
    # @return [Boolean] true if the public key is EC, false otherwise
    def ec?
      @cert.public_key.kind_of?(OpenSSL::PKey::EC)
    end

    # Returns the bit strength of the key used to create the certificate
    #
    # @return [Integer] integer value of bit strength
    def bit_strength
      if self.rsa?
        return @cert.public_key.n.num_bits
      elsif self.dsa?
        return @cert.public_key.p.num_bits
      elsif self.ec?
        raise R509::R509Error, 'Bit strength is not available for EC at this time.'
      end
    end

    # Returns the short name of the elliptic curve used to generate the public key
    # if the key is EC. If not, raises an error.
    #
    # @return [String] elliptic curve name
    def curve_name
      if self.ec?
        @cert.public_key.group.curve_name
      else
        raise R509::R509Error, 'Curve name is only available with EC certs'
      end
    end

    # Returns signature algorithm
    #
    # @return [String] value of the signature algorithm. E.g. sha1WithRSAEncryption, sha256WithRSAEncryption, md5WithRSAEncryption, et cetera
    def signature_algorithm
      @cert.signature_algorithm
    end

    # Returns key algorithm (RSA, DSA, EC)
    #
    # @return [String] value of the key algorithm. RSA, DSA, EC
    def key_algorithm
      if self.rsa?
        "RSA"
      elsif self.dsa?
        "DSA"
      elsif self.ec?
        "EC"
      end
    end

    # Writes the Cert into the PEM format
    # @param [String, #write] filename_or_io Either a string of the path for
    #  the file that you'd like to write, or an IO-like object.
    def write_pem(filename_or_io)
      write_data(filename_or_io, @cert.to_pem)
    end

    # Writes the Cert into the DER format
    # @param [String, #write] filename_or_io Either a string of the path for
    #  the file that you'd like to write, or an IO-like object.
    def write_der(filename_or_io)
      write_data(filename_or_io, @cert.to_der)
    end

    # Writes cert and key into PKCS12 format using OpenSSL defaults for encryption (des3)
    # @param [String, #write] filename_or_io Either a string of the path for
    #  the file that you'd like to write, or an IO-like object.
    # @param [String] password password
    # @param [String] friendly_name An optional string to encode in the PKCS12 for friendlyName. defaults to "r509 pkcs12"
    def write_pkcs12(filename_or_io,password,friendly_name='r509 pkcs12')
      if @key.nil?
        raise R509::R509Error, "Writing a PKCS12 requires both key and cert"
      end
      pkcs12 = OpenSSL::PKCS12.create(password,friendly_name,@key.key,@cert)
      write_data(filename_or_io, pkcs12.to_der)
    end

    # Checks the given CRL for this certificate's serial number. Note that this does NOT
    # check to verify that the CRL you're checking is signed by the same CA as the cert
    # so do that check yourself
    #
    # @param [R509::Crl::SignedList] r509_crl A CRL from the CA that issued this certificate.
    def is_revoked_by_crl?( r509_crl )
      return r509_crl.revoked?( self.serial )
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
        @r509_extensions = Extensions.wrap_openssl_extensions( self.cert.extensions )
      end

      return @r509_extensions
    end

    # Returns an array of OpenSSL::X509::Extension objects representing the
    # extensions that do not have R509 implementations.
    #
    # @return [Array] An array of OpenSSL::X509::Extension objects.
    def unknown_extensions
      return Extensions.get_unknown_extensions( self.cert.extensions )
    end

    #
    # Shortcuts to extensions
    #

    # Returns this object's BasicConstraints extension as an R509 extension
    #
    # @return [R509::Cert::Extensions::BasicConstraints] The object, or nil
    # if this cert does not have a BasicConstraints extension.
    def basic_constraints
      return extensions[R509::Cert::Extensions::BasicConstraints]
    end

    # Returns this object's KeyUsage extension as an R509 extension
    #
    # @return [R509::Cert::Extensions::KeyUsage] The object, or nil
    # if this cert does not have a KeyUsage extension.
    def key_usage
      return extensions[R509::Cert::Extensions::KeyUsage]
    end
    alias_method :ku, :key_usage

    # Returns this object's ExtendedKeyUsage extension as an R509 extension
    #
    # @return [R509::Cert::Extensions::ExtendedKeyUsage] The object, or nil
    # if this cert does not have a ExtendedKeyUsage extension.
    def extended_key_usage
      return extensions[R509::Cert::Extensions::ExtendedKeyUsage]
    end
    alias_method :eku, :extended_key_usage

    # Returns this object's SubjectKeyIdentifier extension as an R509 extension
    #
    # @return [R509::Cert::Extensions::SubjectKeyIdentifier] The object, or nil
    # if this cert does not have a SubjectKeyIdentifier extension.
    def subject_key_identifier
      return extensions[R509::Cert::Extensions::SubjectKeyIdentifier]
    end

    # Returns this object's AuthorityKeyIdentifier extension as an R509 extension
    #
    # @return [R509::Cert::Extensions::AuthorityKeyIdentifier] The object, or nil
    # if this cert does not have a AuthorityKeyIdentifier extension.
    def authority_key_identifier
      return extensions[R509::Cert::Extensions::AuthorityKeyIdentifier]
    end

    # Returns this object's SubjectAlternativeName extension as an R509 extension
    #
    # @return [R509::Cert::Extensions::SubjectAlternativeName] The object, or nil
    # if this cert does not have a SubjectAlternativeName extension.
    def subject_alternative_name
      return extensions[R509::Cert::Extensions::SubjectAlternativeName]
    end
    alias_method :san, :subject_alternative_name
    alias_method :subject_alt_name, :subject_alternative_name

    # Returns this object's AuthorityInfoAccess extension as an R509 extension
    #
    # @return [R509::Cert::Extensions::AuthorityInfoAccess] The object, or nil
    # if this cert does not have a AuthorityInfoAccess extension.
    def authority_info_access
      return extensions[R509::Cert::Extensions::AuthorityInfoAccess]
    end
    alias_method :aia, :authority_info_access

    # Returns this object's CrlDistributionPoints extension as an R509 extension
    #
    # @return [R509::Cert::Extensions::CrlDistributionPoints] The object, or nil
    # if this cert does not have a CrlDistributionPoints extension.
    def crl_distribution_points
      return extensions[R509::Cert::Extensions::CrlDistributionPoints]
    end
    alias_method :cdp, :crl_distribution_points

    # Returns true if the OCSP No Check extension is present
    # (value is irrelevant to this extension)
    #
    # @return [Boolean] presence/absence of the nocheck extension
    def ocsp_no_check?
      return (extensions.has_key?(R509::Cert::Extensions::OCSPNoCheck))
    end

    # Returns this object's CertificatePolicies extension as an R509 extension
    #
    # @return [R509::Cert::Extensions::CertificatePolicies] The object, or nil
    # if this cert does not have a CertificatePolicies extension.
    def certificate_policies
      return extensions[R509::Cert::Extensions::CertificatePolicies]
    end


    private
    # This method exists only to provide a friendlier error msg if you attempt to
    # parse a CSR as a certificate. All for Sean
    def csr_check(cert)
      begin
        csr = OpenSSL::X509::Request.new cert
        raise R509Error, 'Cert provided is actually a certificate signing request.'
      rescue OpenSSL::X509::RequestError
        # do nothing, it shouldn't be a CSR anyway!
      end
    end

    def parse_certificate(cert)
      @cert = OpenSSL::X509::Certificate.new cert
    end

    def associate_private_key(key)
      if not key.nil?
        if not @cert.public_key.to_der == key.public_key.to_der then
          raise R509Error, 'Key does not match cert.'
        end
        @key = key
      end
    end

  end
end
