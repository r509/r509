require 'openssl'
require 'r509/asn1'
require 'set'

module R509
  class Cert
    # module to contain extension classes for R509::Cert
    module Extensions

      private
      R509_EXTENSION_CLASSES = Set.new

      # Registers a class as being an R509 certificate extension class. Registered
      # classes are used by #wrap_openssl_extensions to wrap OpenSSL extensions
      # in R509 extensions, based on the OID.
      def self.register_class( r509_ext_class )
        raise ArgumentError.new("R509 certificate extensions must have an OID") if r509_ext_class::OID.nil?
        R509_EXTENSION_CLASSES << r509_ext_class
      end


      public
      # Implements the BasicConstraints certificate extension, with methods to
      # provide access to the components and meaning of the extension's contents.
      class BasicConstraints < OpenSSL::X509::Extension
        # friendly name for BasicConstraints OID
        OID = "basicConstraints"
        Extensions.register_class(self)

        attr_reader :path_length

        # See OpenSSL::X509::Extension#initialize
        def initialize(*args)
          super(*args)

          data = R509::ASN1.get_extension_payload(self)
          @is_ca = false
          #   BasicConstraints ::= SEQUENCE {
          #        cA                      BOOLEAN DEFAULT FALSE,
          #        pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
          data.entries.each do |entry|
            if entry.kind_of?(OpenSSL::ASN1::Boolean)
              # since the boolean is optional it may not be present
              @is_ca = entry.value
            else
              # There are only two kinds of entries permitted so anything
              # else is an integer pathlength
              @path_length = entry.value
            end
          end
        end

        def is_ca?()
          return @is_ca == true
        end

        # Returns true if the path length allows this certificate to be used to
        # create subordinate signing certificates beneath it. Does not check if
        # there is a pathlen restriction in the cert chain above the current cert
        def allows_sub_ca?()
          return false if @path_length.nil?
          return @path_length > 0
        end
      end

      # Implements the KeyUsage certificate extension, with methods to
      # provide access to the components and meaning of the extension's contents.
      class KeyUsage < OpenSSL::X509::Extension
        # friendly name for KeyUsage OID
        OID = "keyUsage"
        Extensions.register_class(self)

        # An array of the key uses allowed.
        attr_reader :allowed_uses

        # OpenSSL short name for Digital Signature
        AU_DIGITAL_SIGNATURE = "digitalSignature"
        # OpenSSL short name for Non Repudiation (also known as content commitment)
        AU_NON_REPUDIATION = "nonRepudiation"
        # OpenSSL short name for Key Encipherment
        AU_KEY_ENCIPHERMENT = "keyEncipherment"
        # OpenSSL short name for Data Encipherment
        AU_DATA_ENCIPHERMENT = "dataEncipherment"
        # OpenSSL short name for Key Agreement
        AU_KEY_AGREEMENT = "keyAgreement"
        # OpenSSL short name for Certificate Sign
        AU_KEY_CERT_SIGN = "keyCertSign"
        # OpenSSL short name for CRL Sign
        AU_CRL_SIGN = "cRLSign"
        # OpenSSL short name for Encipher Only
        AU_ENCIPHER_ONLY = "encipherOnly"
        # OpenSSL short name for Decipher Only
        AU_DECIPHER_ONLY = "decipherOnly"

        # See OpenSSL::X509::Extension#initialize
        def initialize(*args)
          super(*args)

          data = R509::ASN1.get_extension_payload(self)

          # There are 9 possible bits, which means we need 2 bytes
          # to represent them all. When the last bit is not set
          # the second byte is not encoded. let's add it back so we can
          # have the full bitmask for comparison
          if data.size == 1
            data = data + "\0"
          end
          bit_mask = data.unpack('n')[0] # treat it as a 16-bit unsigned big endian
          #      KeyUsage ::= BIT STRING {
          #           digitalSignature        (0),
          #           nonRepudiation          (1), -- recent editions of X.509 have
          #                                -- renamed this bit to contentCommitment
          #           keyEncipherment         (2),
          #           dataEncipherment        (3),
          #           keyAgreement            (4),
          #           keyCertSign             (5),
          #           cRLSign                 (6),
          #           encipherOnly            (7),
          #           decipherOnly            (8) }
          @allowed_uses = []
          if bit_mask & 0b1000000000000000 > 0
            @digital_signature = true
            @allowed_uses << AU_DIGITAL_SIGNATURE
          end
          if bit_mask & 0b0100000000000000 > 0
            @non_repudiation = true
            @allowed_uses << AU_NON_REPUDIATION
          end
          if bit_mask & 0b0010000000000000 > 0
            @key_encipherment = true
            @allowed_uses << AU_KEY_ENCIPHERMENT
          end
          if bit_mask & 0b0001000000000000 > 0
            @data_encipherment = true
            @allowed_uses << AU_DATA_ENCIPHERMENT
          end
          if bit_mask & 0b0000100000000000 > 0
            @key_agreement = true
            @allowed_uses << AU_KEY_AGREEMENT
          end
          if bit_mask & 0b0000010000000000 > 0
            @key_cert_sign = true
            @allowed_uses << AU_KEY_CERT_SIGN
          end
          if bit_mask & 0b0000001000000000 > 0
            @crl_sign = true
            @allowed_uses << AU_CRL_SIGN
          end
          if bit_mask & 0b0000000100000000 > 0
            @encipher_only = true
            @allowed_uses << AU_ENCIPHER_ONLY
          end
          if bit_mask & 0b0000000010000000 > 0
            @decipher_only = true
            @allowed_uses << AU_DECIPHER_ONLY
          end
        end

        # Returns true if the given use is allowed by this extension.
        # @param [String] friendly_use_name key usage short name (e.g. digitalSignature, cRLSign, etc)
        #   or one of the AU_* constants in this class
        # @return [Boolean]
        def allows?( friendly_use_name )
          @allowed_uses.include?( friendly_use_name )
        end

        def digital_signature?
          (@digital_signature == true)
        end

        def non_repudiation?
          (@non_repudiation == true)
        end

        def key_encipherment?
          (@key_encipherment == true)
        end

        def data_encipherment?
          (@data_encipherment == true)
        end

        def key_agreement?
          (@key_agreement == true)
        end

        def key_cert_sign?
          (@key_cert_sign == true)
        end

        def crl_sign?
          (@crl_sign == true)
        end

        def encipher_only?
          (@encipher_only == true)
        end

        def decipher_only?
          (@decipher_only == true)
        end
      end

      # Implements the ExtendedKeyUsage certificate extension, with methods to
      # provide access to the components and meaning of the extension's contents.
      class ExtendedKeyUsage < OpenSSL::X509::Extension
        # friendly name for EKU OID
        OID = "extendedKeyUsage"
        Extensions.register_class(self)

        # The OpenSSL short name for TLS Web Server Authentication
        AU_WEB_SERVER_AUTH = "serverAuth"
        # The OpenSSL short name for TLS Web Client Authentication
        AU_WEB_CLIENT_AUTH = "clientAuth"
        # The OpenSSL short name for Code Signing
        AU_CODE_SIGNING = "codeSigning"
        # The OpenSSL short name for E-mail Protection
        AU_EMAIL_PROTECTION = "emailProtection"
        # The OpenSSL short name for OCSP Signing
        AU_OCSP_SIGNING = "OCSPSigning"
        # The OpenSSL short name for Time Stamping
        AU_TIME_STAMPING = "timeStamping"
        # The OpenSSL short name for Any Extended Key Usage
        AU_ANY_EXTENDED_KEY_USAGE = "anyExtendedKeyUsage"

        attr_reader :allowed_uses

        # See OpenSSL::X509::Extension#initialize
        def initialize(*args)
          super(*args)

          @allowed_uses = []
          data = R509::ASN1.get_extension_payload(self)

          data.entries.each do |eku|
            #   The following key usage purposes are defined:
            #
            #   anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 }
            #
            #   id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }
            #   id-kp-serverAuth             OBJECT IDENTIFIER ::= { id-kp 1 }
            #   -- TLS WWW server authentication
            #   -- Key usage bits that may be consistent: digitalSignature,
            #   -- keyEncipherment or keyAgreement
            #
            #   id-kp-clientAuth             OBJECT IDENTIFIER ::= { id-kp 2 }
            #   -- TLS WWW client authentication
            #   -- Key usage bits that may be consistent: digitalSignature
            #   -- and/or keyAgreement
            #
            #   id-kp-codeSigning             OBJECT IDENTIFIER ::= { id-kp 3 }
            #   -- Signing of downloadable executable code
            #   -- Key usage bits that may be consistent: digitalSignature
            #
            #   id-kp-emailProtection         OBJECT IDENTIFIER ::= { id-kp 4 }
            #   -- Email protection
            #   -- Key usage bits that may be consistent: digitalSignature,
            #   -- nonRepudiation, and/or (keyEncipherment or keyAgreement)
            #
            #   id-kp-timeStamping            OBJECT IDENTIFIER ::= { id-kp 8 }
            #   -- Binding the hash of an object to a time
            #   -- Key usage bits that may be consistent: digitalSignature
            #   -- and/or nonRepudiation
            #
            #   id-kp-OCSPSigning            OBJECT IDENTIFIER ::= { id-kp 9 }
            #   -- Signing OCSP responses
            #   -- Key usage bits that may be consistent: digitalSignature
            #   -- and/or nonRepudiation

            case eku.value
            when AU_WEB_SERVER_AUTH
              @web_server_authentication = true
            when AU_WEB_CLIENT_AUTH
              @web_client_authentication = true
            when AU_CODE_SIGNING
              @code_signing = true
            when AU_EMAIL_PROTECTION
              @email_protection = true
            when AU_OCSP_SIGNING
              @ocsp_signing = true
            when AU_TIME_STAMPING
              @time_stamping = true
            when AU_ANY_EXTENDED_KEY_USAGE
              @any_extended_key_usage = true
            end
            @allowed_uses << eku.value
          end
        end

        # Returns true if the given use is allowed by this extension.
        # @param [string] friendly_use_name One of the AU_* constants in this class.
        def allows?( friendly_use_name )
          @allowed_uses.include?( friendly_use_name )
        end

        def web_server_authentication?
          (@web_server_authentication == true)
        end

        def web_client_authentication?
          (@web_client_authentication == true)
        end

        def code_signing?
          (@code_signing == true)
        end

        def email_protection?
          (@email_protection == true)
        end

        def ocsp_signing?
          (@ocsp_signing == true)
        end

        def time_stamping?
          (@time_stamping == true)
        end

        def any_extended_key_usage?
          (@any_extended_key_usage == true)
        end
      end

      # Implements the SubjectKeyIdentifier certificate extension, with methods to
      # provide access to the components and meaning of the extension's contents.
      class SubjectKeyIdentifier < OpenSSL::X509::Extension
        # friendly name for Subject Key Identifier OID
        OID = "subjectKeyIdentifier"
        Extensions.register_class(self)

        # @return value of key
        def key()
          return self.value
        end
      end

      # Implements the AuthorityKeyIdentifier certificate extension, with methods to
      # provide access to the components and meaning of the extension's contents.
      class AuthorityKeyIdentifier < OpenSSL::X509::Extension
        # friendly name for Authority Key Identifier OID
        OID = "authorityKeyIdentifier"
        Extensions.register_class(self)

      end

      # Implements the SubjectAlternativeName certificate extension, with methods to
      # provide access to the components and meaning of the extension's contents.
      class SubjectAlternativeName < OpenSSL::X509::Extension
        # friendly name for SAN OID
        OID = "subjectAltName"
        Extensions.register_class(self)

        attr_reader :general_names

        # See OpenSSL::X509::Extension#initialize
        def initialize(*args)
          super(*args)

          data = R509::ASN1.get_extension_payload(self)
          @general_names = R509::ASN1::GeneralNames.new
          data.entries.each do |gn|
            @general_names.add_item(gn)
          end
        end

        # @return [Array<String>] DNS names
        def dns_names
          @general_names.dns_names
        end

        # @return [Array<String>] IP addresses formatted as dotted quad
        def ip_addresses
          @general_names.ip_addresses
        end

        # @return [Array<String>] email addresses
        def rfc_822_names
          @general_names.rfc_822_names
        end

        # @return [Array<String>] URIs (not typically found in SAN extensions)
        def uris
          @general_names.uris
        end

        # @return [Array] array of hashes of form { :type => "", :value => "" } that preserve the order found
        #   in the extension
        def names
          @general_names.names
        end
      end

      # Implements the AuthorityInfoAccess certificate extension, with methods to
      # provide access to the components and meaning of the extension's contents.
      class AuthorityInfoAccess < OpenSSL::X509::Extension
        # friendly name for AIA OID
        OID = "authorityInfoAccess"
        Extensions.register_class(self)

        # An array of the OCSP data, if any
        attr_reader :ocsp
        # An array of the CA issuers data, if any
        attr_reader :ca_issuers

        # See OpenSSL::X509::Extension#initialize
        def initialize(*args)
          super(*args)

          data = R509::ASN1.get_extension_payload(self)
          @ocsp= R509::ASN1::GeneralNames.new
          @ca_issuers= R509::ASN1::GeneralNames.new
          data.entries.each do |access_description|
            #   AccessDescription  ::=  SEQUENCE {
            #           accessMethod          OBJECT IDENTIFIER,
            #           accessLocation        GeneralName  }
            case access_description.entries[0].value
            when "OCSP"
              @ocsp.add_item(access_description.entries[1])
            when "caIssuers"
              @ca_issuers.add_item(access_description.entries[1])
            end
          end
        end
      end

      # Implements the CRLDistributionPoints certificate extension, with methods to
      # provide access to the components and meaning of the extension's contents.
      class CRLDistributionPoints < OpenSSL::X509::Extension
        # friendly name for CDP OID
        OID = "crlDistributionPoints"
        Extensions.register_class(self)

        # An array of the CRL URIs, if any
        attr_reader :crl

        # See OpenSSL::X509::Extension#initialize
        def initialize(*args)
          super(*args)

          @crl= R509::ASN1::GeneralNames.new
          data = R509::ASN1.get_extension_payload(self)
          data.entries.each do |distribution_point|
            #   DistributionPoint ::= SEQUENCE {
            #        distributionPoint       [0]     DistributionPointName OPTIONAL,
            #        reasons                 [1]     ReasonFlags OPTIONAL,
            #        cRLIssuer               [2]     GeneralNames OPTIONAL }
            #   DistributionPointName ::= CHOICE {
            #        fullName                [0]     GeneralNames,
            #        nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
            # We're only going to handle DistributionPointName [0] for now
            # so grab entries[0] and then get the fullName with value[0]
            # and the value of that ASN1Data with value[0] again
            @crl.add_item(distribution_point.entries[0].value[0].value[0])
          end
        end
      end

      # Implements the OCSP noCheck certificate extension
      class OCSPNoCheck < OpenSSL::X509::Extension
        # friendly name for OCSP No Check
        OID = "noCheck"
        Extensions.register_class(self)

        # See OpenSSL::X509::Extension#initialize
        def initialize(*args)
          super(*args)
        end
      end


      # Implements the CertificatePolicies certificate extension, with methods to
      # provide access to the components and meaning of the extension's contents.
      class CertificatePolicies < OpenSSL::X509::Extension
        # friendly name for CP OID
        OID = "certificatePolicies"
        Extensions.register_class(self)
        attr_reader :policies

        def initialize(*args)
          @policies = []
          super(*args)

          data = R509::ASN1.get_extension_payload(self)

          # each element of this sequence should be part of a policy + qualifiers
          #   certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
          data.each do |cp|
            @policies << R509::ASN1::PolicyInformation.new(cp)
          end if data.respond_to?(:each)
        end
      end


      #
      # Helper class methods
      #

      # Takes OpenSSL::X509::Extension objects and wraps each in the appropriate
      # R509::Cert::Extensions object, and returns them in a hash. The hash is
      # keyed with the R509 extension class. Extensions without an R509
      # implementation are ignored (see #get_unknown_extensions).
      def self.wrap_openssl_extensions( extensions )
        r509_extensions = {}
        extensions.each do |openssl_extension|
          R509_EXTENSION_CLASSES.each do |r509_class|
            if ( r509_class::OID.downcase == openssl_extension.oid.downcase )
              if r509_extensions.has_key?(r509_class)
                raise ArgumentError.new("Only one extension object allowed per OID")
              end

              r509_extensions[r509_class] = r509_class.new( openssl_extension )
              break
            end
          end
        end

        return r509_extensions
      end

      # Given a list of OpenSSL::X509::Extension objects, returns those without
      # an R509 implementation.
      def self.get_unknown_extensions( extensions )
        unknown_extensions = []
        extensions.each do |openssl_extension|
          match_found = false
          R509_EXTENSION_CLASSES.each do |r509_class|
            if ( r509_class::OID.downcase == openssl_extension.oid.downcase )
              match_found = true
              break
            end
          end
          # if we make it this far (without breaking), we didn't match
          unknown_extensions << openssl_extension unless match_found
        end

        return unknown_extensions
      end
    end
  end
end

