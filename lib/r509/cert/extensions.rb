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

      # @private
      def self.calculate_critical(critical,default)
        if critical.kind_of?(TrueClass) or critical.kind_of?(FalseClass)
          critical
        else
          default
        end
      end

      public
      # RFC 5280 Description (see: http://www.ietf.org/rfc/rfc5280.txt)
      #
      # The basic constraints extension identifies whether the subject of the
      # certificate is a CA and the maximum depth of valid certification
      # paths that include this certificate.
      #
      # You can use this extension to parse an existing extension for easy access
      # to the contents or create a new one.
      class BasicConstraints < OpenSSL::X509::Extension
        include R509::ValidationMixin

        # friendly name for BasicConstraints OID
        OID = "basicConstraints"
        Extensions.register_class(self)

        # returns the path length (if present)
        # @return [Integer,nil]
        attr_reader :path_length

        # This method takes a hash or an existing Extension object to parse
        # @option arg :ca [Boolean]
        # @option arg :path_length [Integer]
        # @option arg :critical [Boolean] (true)
        def initialize(arg)
          if arg.kind_of?(Hash)
            arg = build_extension(arg)
          end

          super(arg)

          data = R509::ASN1.get_extension_payload(self)
          @is_ca = false
          #   BasicConstraints ::= SEQUENCE {
          #        cA                      BOOLEAN DEFAULT FALSE,
          #        pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
          data.entries.each do |entry|
            if entry.kind_of?(OpenSSL::ASN1::Boolean)
              @is_ca = entry.value
            else
              # There are only two kinds of entries permitted so anything
              # else is an integer pathlength. it is in OpenSSL::BN form by default
              # but that's annoying so let's cast it.
              @path_length = entry.value.to_i
            end
          end
        end

        # Check whether the extension value would make the parent certificate a CA
        # @return [Boolean]
        def is_ca?
          return @is_ca == true
        end

        # Returns true if the path length allows this certificate to be used to
        # create subordinate signing certificates beneath it. Does not check if
        # there is a pathlen restriction in the cert chain above the current cert
        # @return [Boolean]
        def allows_sub_ca?
          return false unless is_ca?
          return true if @path_length.nil?
          return @path_length > 0
        end

        private

        # @private
        def build_extension(arg)
          validate_basic_constraints(arg)
          ef = OpenSSL::X509::ExtensionFactory.new
          if arg[:ca] == true
            bc_value = "CA:TRUE"
            if not arg[:path_length].nil?
              bc_value += ",pathlen:#{arg[:path_length]}"
            end
          else
            bc_value = "CA:FALSE"
          end
          critical = R509::Cert::Extensions.calculate_critical(arg[:critical], true)
          return ef.create_extension("basicConstraints", bc_value, critical)
        end
      end

      # RFC 5280 Description (see: http://www.ietf.org/rfc/rfc5280.txt)
      #
      # The key usage extension defines the purpose (e.g., encipherment,
      # signature, certificate signing) of the key contained in the
      # certificate.  The usage restriction might be employed when a key that
      # could be used for more than one operation is to be restricted.  For
      # example, when an RSA key should be used only to verify signatures on
      # objects other than public key certificates and CRLs, the
      # digitalSignature and/or nonRepudiation bits would be asserted.
      # Likewise, when an RSA key should be used only for key management, the
      # keyEncipherment bit would be asserted.
      #
      # You can use this extension to parse an existing extension for easy access
      # to the contents or create a new one.
      class KeyUsage < OpenSSL::X509::Extension
        include R509::ValidationMixin

        # friendly name for KeyUsage OID
        OID = "keyUsage"
        Extensions.register_class(self)

        # An array (of strings) of the key uses allowed.
        # @return [Array,nil]
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

        # This method takes a hash or an existing Extension object to parse
        # @option arg :key_usage [Array]
        # @option arg :critical [Boolean] (false)
        def initialize(arg)
          if arg.kind_of?(Hash)
            validate_usage(arg[:key_usage],'key_usage')
            ef = OpenSSL::X509::ExtensionFactory.new
            critical = R509::Cert::Extensions.calculate_critical(arg[:critical], false)
            arg = ef.create_extension("keyUsage", arg[:key_usage].join(","),critical)
          end

          super(arg)

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

      # RFC 5280 Description (see: http://www.ietf.org/rfc/rfc5280.txt)
      #
      # This extension indicates one or more purposes for which the certified
      # public key may be used, in addition to or in place of the basic
      # purposes indicated in the key usage extension.  In general, this
      # extension will appear only in end entity certificates.
      #
      # You can use this extension to parse an existing extension for easy access
      # to the contents or create a new one.
      class ExtendedKeyUsage < OpenSSL::X509::Extension
        include R509::ValidationMixin

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

        # an array (of strings) of the extended key uses allowed
        # @return [Array,nil]
        attr_reader :allowed_uses

        # This method takes a hash or an existing Extension object to parse
        # @option arg :extended_key_usage [Array]
        # @option arg :critical [Boolean] (false)
        def initialize(arg)
          if arg.kind_of?(Hash)
            validate_usage(arg[:extended_key_usage],'extended_key_usage')
            ef = OpenSSL::X509::ExtensionFactory.new
            critical = R509::Cert::Extensions.calculate_critical(arg[:critical], false)
            arg = ef.create_extension("extendedKeyUsage", arg[:extended_key_usage].join(","),critical)
          end

          super(arg)

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

      # RFC 5280 Description (see: http://www.ietf.org/rfc/rfc5280.txt)
      #
      # The subject key identifier extension provides a means of identifying
      # certificates that contain a particular public key.
      #
      # You can use this extension to parse an existing extension for easy access
      # to the contents or create a new one.
      class SubjectKeyIdentifier < OpenSSL::X509::Extension
        include R509::ValidationMixin

        # friendly name for Subject Key Identifier OID
        OID = "subjectKeyIdentifier"
        # default extension behavior when generating
        SKI_EXTENSION_DEFAULT = "hash"
        Extensions.register_class(self)

        # This method takes a hash or an existing Extension object to parse
        # @option arg :public_key [OpenSSL::PKey] (Cert/CSR/PrivateKey return this type from #public_key)
        # @option arg :critical [Boolean] (false)
        def initialize(arg)
          if arg.kind_of?(Hash)
            validate_subject_key_identifier(arg)
            ef = OpenSSL::X509::ExtensionFactory.new
            cert = OpenSSL::X509::Certificate.new
            cert.public_key = arg[:public_key]
            ef.subject_certificate = cert
            critical = R509::Cert::Extensions.calculate_critical(arg[:critical], false)
            arg = ef.create_extension("subjectKeyIdentifier", SKI_EXTENSION_DEFAULT, critical)
          end
          super(arg)
        end

        # @return value of key
        def key
          return self.value
        end
      end

      # RFC 5280 Description (see: http://www.ietf.org/rfc/rfc5280.txt)
      #
      # The authority key identifier extension provides a means of
      # identifying the public key corresponding to the private key used to
      # sign a certificate.  This extension is used where an issuer has
      # multiple signing keys (either due to multiple concurrent key pairs or
      # due to changeover).  The identification MAY be based on either the
      # key identifier (the subject key identifier in the issuer's
      # certificate) or the issuer name and serial number.
      #
      # You can use this extension to parse an existing extension for easy access
      # to the contents or create a new one.
      class AuthorityKeyIdentifier < OpenSSL::X509::Extension
        include R509::ValidationMixin

        # friendly name for Authority Key Identifier OID
        OID = "authorityKeyIdentifier"
        # default extension behavior when generating
        AKI_EXTENSION_DEFAULT = "keyid"
        Extensions.register_class(self)

        # key_identifier, if present, will be a hex string delimited by colons
        # @return [String,nil]
        attr_reader :key_identifier
        # authority_cert_issuer, if present, will be a GeneralName object
        # @return [R509::ASN1::GeneralName,nil]
        attr_reader :authority_cert_issuer
        # authority_cert_serial_number, if present, will be a hex string delimited by colons
        # @return [String,nil]
        attr_reader :authority_cert_serial_number


        # @option arg :public_key [OpenSSL::PKey] Required if embedding keyid
        # @option arg :issuer_subject [R509::Subject] Required if embedding issuer
        # @option arg :value [String] (keyid) For the rules of :value see: http://www.openssl.org/docs/apps/x509v3_config.html#Authority_Key_Identifier_. If you want to embed issuer you MUST supply :issuer_certificate and not :public_key
        # @option arg :critical [Boolean] (false)
        def initialize(arg)
          if arg.kind_of?(Hash)
            arg = build_extension(arg)
          end

          super(arg)

          data = R509::ASN1.get_extension_payload(self)
          #   AuthorityKeyIdentifier ::= SEQUENCE {
          #      keyIdentifier             [0] KeyIdentifier           OPTIONAL,
          #      authorityCertIssuer       [1] GeneralNames            OPTIONAL,
          #      authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
          data.entries.each do |el|
            case el.tag
            when 0
              @key_identifier = el.value.unpack("H*")[0].upcase.scan(/../).join(":")
            when 1
              @authority_cert_issuer = R509::ASN1::GeneralName.new(el.value.first)
            when 2
              arr = el.value.unpack("H*")[0].upcase.scan(/../)
              # OpenSSL's convention is to drop leading 00s, so let's strip that off if
              # present
              if arr[0] == "00"
                arr.delete_at(0)
              end
              @authority_cert_serial_number = arr.join(":")
            end
          end

        end

        private

        # @private
        def build_extension(arg)
          arg[:value] = AKI_EXTENSION_DEFAULT unless not arg[:value].nil?
          validate_authority_key_identifier(arg)
          ef = OpenSSL::X509::ExtensionFactory.new
          fake_cert = OpenSSL::X509::Certificate.new
          fake_cert.extensions = [R509::Cert::Extensions::SubjectKeyIdentifier.new(:public_key => arg[:public_key])] unless arg[:public_key].nil?
          fake_cert.subject = arg[:issuer_subject].name unless arg[:issuer_subject].nil?
          ef.issuer_certificate = fake_cert
          critical = R509::Cert::Extensions.calculate_critical(arg[:critical], false)
          return ef.create_extension("authorityKeyIdentifier", arg[:value], critical) # this could also be keyid:always,issuer:always
        end

      end

      # RFC 5280 Description (see: http://www.ietf.org/rfc/rfc5280.txt)
      #
      # The subject alternative name extension allows identities to be bound
      # to the subject of the certificate.  These identities may be included
      # in addition to or in place of the identity in the subject field of
      # the certificate.  Defined options include an Internet electronic mail
      # address, a DNS name, an IP address, and a Uniform Resource Identifier
      # (URI).  Other options exist, including completely local definitions.
      # Multiple name forms, and multiple instances of each name form, MAY be
      # included.  Whenever such identities are to be bound into a
      # certificate, the subject alternative name (or issuer alternative
      # name) extension MUST be used; however, a DNS name MAY also be
      # represented in the subject field using the domainComponent attribute
      # as described in Section 4.1.2.4.  Note that where such names are
      # represented in the subject field implementations are not required to
      # convert them into DNS names.
      #
      # You can use this extension to parse an existing extension for easy access
      # to the contents or create a new one.
      class SubjectAlternativeName < OpenSSL::X509::Extension
        include R509::ValidationMixin

        # friendly name for SAN OID
        OID = "subjectAltName"
        Extensions.register_class(self)

        # @return [R509::ASN1::GeneralNames]
        attr_reader :general_names

        # This method takes a hash or an existing Extension object to parse
        #
        # @option arg :names [Array,R509::ASN1::GeneralNames] If you supply an Array
        #   it will be parsed by R509::ASN1.general_name_parser to
        #   determine the type of each element. If you prefer to specify it yourself you
        #   can pass a pre-existing GeneralNames object.
        # @option arg :critical [Boolean] (false)
        def initialize(arg)
          if arg.kind_of?(Hash)
            arg = build_extension(arg)
          end
          super(arg)

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

        # @return [Array<R509::Subject>] directory names
        def directory_names
          @general_names.directory_names
        end

        # @return [Array] array of GeneralName objects preserving order found in the extension
        def names
          @general_names.names
        end

        private

        # @private
        def build_extension(arg)
          validate_subject_alternative_name(arg[:names])
          serialize = R509::ASN1.general_name_parser(arg[:names]).serialize_names
          ef = OpenSSL::X509::ExtensionFactory.new
          ef.config = OpenSSL::Config.parse(serialize[:conf])
          critical = R509::Cert::Extensions.calculate_critical(arg[:critical], false)
          return ef.create_extension("subjectAltName", serialize[:extension_string],critical)
        end
      end

      # RFC 5280 Description (see: http://www.ietf.org/rfc/rfc5280.txt)
      #
      # The authority information access extension indicates how to access
      # information and services for the issuer of the certificate in which
      # the extension appears.  Information and services may include on-line
      # validation services and CA policy data.  (The location of CRLs is not
      # specified in this extension; that information is provided by the
      # cRLDistributionPoints extension.)  This extension may be included in
      # end entity or CA certificates.  Conforming CAs MUST mark this
      # extension as non-critical.
      # You can use this extension to parse an existing extension for easy access
      # to the contents or create a new one.
      class AuthorityInfoAccess < OpenSSL::X509::Extension
        include R509::ValidationMixin

        # friendly name for AIA OID
        OID = "authorityInfoAccess"
        Extensions.register_class(self)

        # An R509::ASN1::GeneralNames object of OCSP endpoints (or nil if not present)
        # @return [R509::ASN1::GeneralNames,nil]
        attr_reader :ocsp
        # An R509::ASN1::GeneralNames object of CA Issuers (or nil if not present)
        # @return [R509::ASN1::GeneralNames,nil]
        attr_reader :ca_issuers

        # This method takes a hash or an existing Extension object to parse
        #
        # @option arg :ocsp_location [Array,R509::ASN1::GeneralNames] Array of strings (eg ["http://somedomain.com/something"]) or GeneralNames object
        # @option arg :ca_issuers_location [Array] Array of strings or GeneralNames object
        # @option arg :critical [Boolean] (false)
        def initialize(arg)
          if arg.kind_of?(Hash)
            arg = build_extension(arg)
          end
          super(arg)

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

        private

        # @private
        def build_extension(arg)
          aia = []
          aia_conf = []

          locations = [
            { :key => :ocsp_location, :short_name => 'OCSP' },
            { :key => :ca_issuers_location, :short_name => 'caIssuers' }
          ]

          locations.each do |pair|
            validate_location(pair[:key].to_s,arg[pair[:key]])
            if not arg[pair[:key]].nil?
              gns = R509::ASN1.general_name_parser(arg[pair[:key]])
              gns.names.each do |name|
                serialize = name.serialize_name
                aia.push "#{pair[:short_name]};#{serialize[:extension_string]}"
                aia_conf.push serialize[:conf]
              end
            end
          end

          if not aia.empty?
            ef = OpenSSL::X509::ExtensionFactory.new
            ef.config = OpenSSL::Config.parse(aia_conf.join("\n"))
            critical = R509::Cert::Extensions.calculate_critical(arg[:critical], false)
            return ef.create_extension("authorityInfoAccess",aia.join(","),critical)
          end
        end
      end

      # RFC 5280 Description (see: http://www.ietf.org/rfc/rfc5280.txt)
      #
      # The CRL distribution points extension identifies how CRL information
      # is obtained.  The extension SHOULD be non-critical, but this profile
      # RECOMMENDS support for this extension by CAs and applications.
      # Further discussion of CRL management is contained in Section 5.
      #
      # You can use this extension to parse an existing extension for easy access
      # to the contents or create a new one.
      class CRLDistributionPoints < OpenSSL::X509::Extension
        include R509::ValidationMixin

        # friendly name for CDP OID
        OID = "crlDistributionPoints"
        Extensions.register_class(self)

        # @return [R509::ASN1::GeneralNames,nil]
        attr_reader :crl

        # This method takes a hash or an existing Extension object to parse
        #
        # @option arg :cdp_location [Array,R509::ASN1::GeneralNames] Array of strings (eg ["http://crl.what.com/crl.crl"]) or GeneralNames object
        # @option arg :critical [Boolean] (false)
        def initialize(arg)
          if arg.kind_of?(Hash)
            arg = build_extension(arg)
          end
          super(arg)

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

        private

        # @private
        def build_extension(arg)
          validate_location('cdp_location',arg[:cdp_location])
          serialize = R509::ASN1.general_name_parser(arg[:cdp_location]).serialize_names
          ef = OpenSSL::X509::ExtensionFactory.new
          ef.config = OpenSSL::Config.parse(serialize[:conf])
          critical = R509::Cert::Extensions.calculate_critical(arg[:critical], false)
          return ef.create_extension("crlDistributionPoints", serialize[:extension_string],critical)
        end
      end

      # RFC 2560 Description (see: http://www.ietf.org/rfc/rfc2560.txt)
      #
      # A CA may specify that an OCSP client can trust a responder for the
      # lifetime of the responder's certificate. The CA does so by including
      # the extension id-pkix-ocsp-nocheck. This SHOULD be a non-critical
      # extension. The value of the extension should be NULL. CAs issuing
      # such a certificate should realized that a compromise of the
      # responder's key, is as serious as the compromise of a CA key used to
      # sign CRLs, at least for the validity period of this certificate. CA's
      # may choose to issue this type of certificate with a very short
      # lifetime and renew it frequently.
      #
      # You can use this extension to parse an existing extension for easy access
      # to the contents or create a new one.
      class OCSPNoCheck < OpenSSL::X509::Extension
        include R509::ValidationMixin

        # friendly name for OCSP No Check
        OID = "noCheck"
        Extensions.register_class(self)

        # This method takes a hash or an existing Extension object to parse
        #
        # @option arg :ocsp_no_check [Any] Pass any value. It's irrelevant.
        # @option arg :critical [Boolean] (false)
        def initialize(arg)
          if arg.kind_of?(Hash)
            ef = OpenSSL::X509::ExtensionFactory.new
            critical = R509::Cert::Extensions.calculate_critical(arg[:critical], false)
            arg = ef.create_extension("noCheck","yes",critical)
          end
          super(arg)
        end
      end


      # RFC 5280 Description (see: http://www.ietf.org/rfc/rfc5280.txt)
      #
      # The certificate policies extension contains a sequence of one or more
      # policy information terms, each of which consists of an object
      # identifier (OID) and optional qualifiers.  Optional qualifiers, which
      # MAY be present, are not expected to change the definition of the
      # policy.  A certificate policy OID MUST NOT appear more than once in a
      # certificate policies extension.
      #
      # You can use this extension to parse an existing extension for easy access
      # to the contents or create a new one.
      class CertificatePolicies < OpenSSL::X509::Extension
        include R509::ValidationMixin

        # friendly name for CP OID
        OID = "certificatePolicies"
        Extensions.register_class(self)
        # @return [Array] Array of R509::ASN1::PolicyInformation objects
        attr_reader :policies

        # This method takes a hash or an existing Extension object to parse
        #
        # @option arg :policies [Array] Array of hashes in the same format as passed to R509::Config::CertProfile for certificate policies
        # @option arg :critical [Boolean] (false)
        def initialize(arg)
          if arg.kind_of?(Hash)
            arg = build_extension(arg)
          end
          @policies = []
          super(arg)

          data = R509::ASN1.get_extension_payload(self)

          # each element of this sequence should be part of a policy + qualifiers
          #   certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
          data.each do |cp|
            @policies << R509::ASN1::PolicyInformation.new(cp)
          end if data.respond_to?(:each)
        end

        private

        # @private
        def build_extension(arg)
          validate_certificate_policies(arg[:policies])
          conf = []
          policy_names = ["ia5org"]
          arg[:policies].each_with_index do |policy,i|
            conf << build_conf("certPolicies#{i}",policy,i)
            policy_names << "@certPolicies#{i}"
          end
          ef = OpenSSL::X509::ExtensionFactory.new
          ef.config = OpenSSL::Config.parse(conf.join("\n"))
          critical = R509::Cert::Extensions.calculate_critical(arg[:critical], false)
          return ef.create_extension("certificatePolicies", policy_names.join(","),critical)
        end

        # @private
        def build_conf(section,hash,index)
          conf = ["[#{section}]"]
          conf.push "policyIdentifier=#{hash[:policy_identifier]}" unless hash[:policy_identifier].nil?
          hash[:cps_uris].each_with_index do |cps,idx|
            conf.push "CPS.#{idx+1}=\"#{cps}\""
          end if hash[:cps_uris].respond_to?(:each_with_index)

          user_notice_confs = []
          hash[:user_notices].each_with_index do |un,k|
            conf.push "userNotice.#{k+1}=@user_notice#{k+1}#{index}"
            user_notice_confs.push "[user_notice#{k+1}#{index}]"
            user_notice_confs.push "explicitText=\"#{un[:explicit_text]}\"" unless un[:explicit_text].nil?
            # if org is supplied notice numbers is also required (and vice versa). enforced in CAProfile
            user_notice_confs.push "organization=\"#{un[:organization]}\"" unless un[:organization].nil?
            user_notice_confs.push "noticeNumbers=\"#{un[:notice_numbers]}\"" unless un[:notice_numbers].nil?
          end unless not hash[:user_notices].kind_of?(Array)

          conf.concat(user_notice_confs)
          conf.join "\n"
        end
      end

      # The inhibit anyPolicy extension indicates that the special
      # anyPolicy OID, with the value { 2 5 29 32 0 }, is not considered an
      # explicit match for other certificate policies except when it appears
      # in an intermediate self-issued CA certificate.  The value indicates
      # the number of additional non-self-issued certificates that may appear
      # in the path before anyPolicy is no longer permitted.  For example, a
      # value of one indicates that anyPolicy may be processed in
      # certificates issued by the subject of this certificate, but not in
      # additional certificates in the path.
      #
      # You can use this extension to parse an existing extension for easy access
      # to the contents or create a new one.
      class InhibitAnyPolicy < OpenSSL::X509::Extension
        include R509::ValidationMixin

        # friendly name for CP OID
        OID = "inhibitAnyPolicy"
        Extensions.register_class(self)

        # @return [Integer]
        attr_reader :skip_certs

        # This method takes a hash or an existing Extension object to parse
        #
        # @option arg :skip_certs [Integer]
        # @option arg :critical [Boolean] (true)
        def initialize(arg)
          if arg.kind_of?(Hash)
            validate_inhibit_any_policy(arg[:skip_certs])
            ef = OpenSSL::X509::ExtensionFactory.new
            critical = R509::Cert::Extensions.calculate_critical(arg[:critical], true)
            # must be set critical per RFC 5280
            arg = ef.create_extension("inhibitAnyPolicy",arg[:skip_certs].to_s,critical)
          end
          super(arg)

          #   id-ce-inhibitAnyPolicy OBJECT IDENTIFIER ::=  { id-ce 54 }
          #   InhibitAnyPolicy ::= SkipCerts
          #   SkipCerts ::= INTEGER (0..MAX)
          @skip_certs = R509::ASN1.get_extension_payload(self).to_i # returns a non-negative integer
        end
      end

      # RFC 5280 Description (see: http://www.ietf.org/rfc/rfc5280.txt)
      #
      # The policy constraints extension can be used in certificates issued
      # to CAs.  The policy constraints extension constrains path validation
      # in two ways.  It can be used to prohibit policy mapping or require
      # that each certificate in a path contain an acceptable policy
      # identifier.
      #
      # If the inhibitPolicyMapping field is present, the value indicates the
      # number of additional certificates that may appear in the path before
      # policy mapping is no longer permitted.  For example, a value of one
      # indicates that policy mapping may be processed in certificates issued
      # by the subject of this certificate, but not in additional
      # certificates in the path.
      #
      # If the requireExplicitPolicy field is present, the value of
      # requireExplicitPolicy indicates the number of additional certificates
      # that may appear in the path before an explicit policy is required for
      # the entire path.  When an explicit policy is required, it is
      # necessary for all certificates in the path to contain an acceptable
      # policy identifier in the certificate policies extension.  An
      # acceptable policy identifier is the identifier of a policy required
      # by the user of the certification path or the identifier of a policy
      # that has been declared equivalent through policy mapping.
      #
      # You can use this extension to parse an existing extension for easy access
      # to the contents or create a new one.
      class PolicyConstraints < OpenSSL::X509::Extension
        include R509::ValidationMixin

        # friendly name for CP OID
        OID = "policyConstraints"
        Extensions.register_class(self)

        # @return [Integer,nil]
        attr_reader :require_explicit_policy
        # @return [Integer,nil]
        attr_reader :inhibit_policy_mapping

        # This method takes a hash or an existing Extension object to parse
        #
        # @option arg :require_explicit_policy [Integer]
        # @option arg :inhibit_policy_mapping [Integer]
        # @option arg :critical [Boolean] (true)
        def initialize(arg)
          if arg.kind_of?(Hash)
            arg = build_extension(arg)
          end
          super(arg)

          #   id-ce-policyConstraints OBJECT IDENTIFIER ::=  { id-ce 36 }
          #   PolicyConstraints ::= SEQUENCE {
          #        requireExplicitPolicy           [0] SkipCerts OPTIONAL,
          #        inhibitPolicyMapping            [1] SkipCerts OPTIONAL }
          #
          #   SkipCerts ::= INTEGER (0..MAX)
          data = R509::ASN1.get_extension_payload(self)
          data.each do |pc|
            if pc.tag == 0
              @require_explicit_policy = pc.value.bytes.to_a[0]
            elsif pc.tag == 1
              @inhibit_policy_mapping = pc.value.bytes.to_a[0]
            end
          end
        end

        private

        # @private
        def build_extension(arg)
          validate_policy_constraints(arg)
          constraints = []
          constraints << "requireExplicitPolicy:#{arg[:require_explicit_policy]}" unless arg[:require_explicit_policy].nil?
          constraints << "inhibitPolicyMapping:#{arg[:inhibit_policy_mapping]}" unless arg[:inhibit_policy_mapping].nil?
          ef = OpenSSL::X509::ExtensionFactory.new
          critical = R509::Cert::Extensions.calculate_critical(arg[:critical], true)
          # must be set critical per RFC 5280
          return ef.create_extension("policyConstraints",constraints.join(","),critical)
        end
      end

      # RFC 5280 Description (see: http://www.ietf.org/rfc/rfc5280.txt)
      #
      # The name constraints extension, which MUST be used only in a CA
      # certificate, indicates a name space within which all subject names in
      # subsequent certificates in a certification path MUST be located.
      # Restrictions apply to the subject distinguished name and apply to
      # subject alternative names.  Restrictions apply only when the
      # specified name form is present.  If no name of the type is in the
      # certificate, the certificate is acceptable.
      #
      # Name constraints are not applied to self-issued certificates (unless
      # the certificate is the final certificate in the path).  (This could
      # prevent CAs that use name constraints from employing self-issued
      # certificates to implement key rollover.)
      #
      # Restrictions are defined in terms of permitted or excluded name
      # subtrees.  Any name matching a restriction in the excludedSubtrees
      # field is invalid regardless of information appearing in the
      # permittedSubtrees.  Conforming CAs MUST mark this extension as
      # critical and SHOULD NOT impose name constraints on the x400Address,
      # ediPartyName, or registeredID name forms.  Conforming CAs MUST NOT
      # issue certificates where name constraints is an empty sequence.  That
      # is, either the permittedSubtrees field or the excludedSubtrees MUST
      # be present.
      #
      # You can use this extension to parse an existing extension for easy access
      # to the contents or create a new one.
      class NameConstraints < OpenSSL::X509::Extension
        include R509::ValidationMixin

        # friendly name for CP OID
        OID = "nameConstraints"
        Extensions.register_class(self)

        # @return [R509::ASN1::GeneralNames,nil]
        attr_reader :permitted, :excluded

        #      id-ce-nameConstraints OBJECT IDENTIFIER ::=  { id-ce 30 }
        #      NameConstraints ::= SEQUENCE {
        #           permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
        #           excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
        #
        #      GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
        #
        # per RFC 5280
        # Within this profile, the minimum and maximum fields are not used with
        # any name forms, thus, the minimum MUST be zero, and maximum MUST be
        # absent
        #      GeneralSubtree ::= SEQUENCE {
        #           base                    GeneralName,
        #           minimum         [0]     BaseDistance DEFAULT 0,
        #           maximum         [1]     BaseDistance OPTIONAL }
        #
        #      BaseDistance ::= INTEGER (0..MAX)
        def initialize(arg)
          if arg.kind_of?(Hash)
            arg = build_extension(arg)
          end
          super(arg)

          @permitted = []
          @excluded = []

          data = R509::ASN1.get_extension_payload(self)
          data.each do |gs|
            gs.value.each do |asn_data|
              asn_data.value.each do |obj|
                gn = R509::ASN1::GeneralName.new(obj)
                if gs.tag == 0 # permittedSubtrees
                @permitted << gn
                elsif gs.tag == 1 #excludedSubtrees
                  @excluded << gn
                end
              end
            end
          end
        end

        private

        # @private
        def build_extension(arg)
          validate_name_constraints(arg)
          nc_data = []
          nc_conf = []
          [:permitted,:excluded].each do |permit_exclude|
            if not arg[permit_exclude].nil?
              gns = R509::ASN1::GeneralNames.new
              arg[permit_exclude].each do |p|
                gns.create_item(:type => p[:type], :value => p[:value])
              end
              gns.names.each do |name|
                serialize = name.serialize_name
                nc_data.push "#{permit_exclude.to_s};#{serialize[:extension_string]}"
                nc_conf.push serialize[:conf]
              end
            end
          end

          ef = OpenSSL::X509::ExtensionFactory.new
          ef.config = OpenSSL::Config.parse nc_conf.join("\n")
          critical = R509::Cert::Extensions.calculate_critical(arg[:critical], true)
          # must be set critical per RFC 5280
          return ef.create_extension("nameConstraints",nc_data.join(","),critical)
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

