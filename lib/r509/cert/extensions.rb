require 'openssl'
require 'set'

module R509
  class Cert
    # module to contain extension classes for R509::Cert
    module Extensions

      private
      # Regexes for OpenSSL's parsed values
      DNS_REGEX = /DNS:([^,\n]+)/
      IP_ADDRESS_REGEX = /IP:([^,\n]+)/
      URI_REGEX = /URI:([^,\n]+)/

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

          @is_ca = ! ( self.value =~ /CA:TRUE/ ).nil?
          pathlen_match = self.value.match( /pathlen:(\d+)/ )
          @path_length = pathlen_match[1].to_i unless pathlen_match.nil?
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

        # The OpenSSL friendly name for the "digitalSignature" key use.
        AU_DIGITAL_SIGNATURE = "Digital Signature"
        # The OpenSSL friendly name for the "nonRepudiation" key use.
        AU_NON_REPUDIATION = "Non Repudiation"
        # The OpenSSL friendly name for the "keyEncipherment" key use.
        AU_KEY_ENCIPHERMENT = "Key Encipherment"
        # The OpenSSL friendly name for the "dataEncipherment" key use.
        AU_DATA_ENCIPHERMENT = "Data Encipherment"
        # The OpenSSL friendly name for the "keyAgreement" key use.
        AU_KEY_AGREEMENT = "Key Agreement"
        # The OpenSSL friendly name for the "keyCertSign" key use.
        AU_CERTIFICATE_SIGN = "Certificate Sign"
        # The OpenSSL friendly name for the "cRLSign" key use.
        AU_CRL_SIGN = "CRL Sign"
        # The OpenSSL friendly name for the "encipherOnly" key use.
        AU_ENCIPHER_ONLY = "Encipher Only"
        # The OpenSSL friendly name for the "decipherOnly" key use.
        AU_DECIPHER_ONLY = "Decipher Only"

        # An array of the key uses allowed. See the AU_* constants in this class.
        attr_reader :allowed_uses

        # See OpenSSL::X509::Extension#initialize
        def initialize(*args)
          super(*args)

          @allowed_uses = self.value.split(",").map {|use| use.strip}
        end

        # Returns true if the given use is allowed by this extension.
        # @param [string] friendly_use_name One of the AU_* constants in this class.
        def allows?( friendly_use_name )
          @allowed_uses.include?( friendly_use_name )
        end

        def digital_signature?
          allows?( AU_DIGITAL_SIGNATURE )
        end

        def non_repudiation?
          allows?( AU_NON_REPUDIATION )
        end

        def key_encipherment?
          allows?( AU_KEY_ENCIPHERMENT )
        end

        def data_encipherment?
          allows?( AU_DATA_ENCIPHERMENT )
        end

        def key_agreement?
          allows?( AU_KEY_AGREEMENT )
        end

        def certificate_sign?
          allows?( AU_CERTIFICATE_SIGN )
        end

        def crl_sign?
          allows?( AU_CRL_SIGN )
        end

        def encipher_only?
          allows?( AU_ENCIPHER_ONLY )
        end

        def decipher_only?
          allows?( AU_DECIPHER_ONLY )
        end
      end

      # Implements the ExtendedKeyUsage certificate extension, with methods to
      # provide access to the components and meaning of the extension's contents.
      class ExtendedKeyUsage < OpenSSL::X509::Extension
        # friendly name for EKU OID
        OID = "extendedKeyUsage"
        Extensions.register_class(self)

        # The OpenSSL friendly name for the "serverAuth" extended key use.
        AU_WEB_SERVER_AUTH = "TLS Web Server Authentication"
        # The OpenSSL friendly name for the "clientAuth" extended key use.
        AU_WEB_CLIENT_AUTH = "TLS Web Client Authentication"
        # The OpenSSL friendly name for the "codeSigning" extended key use.
        AU_CODE_SIGNING = "Code Signing"
        # The OpenSSL friendly name for the "emailProtection" extended key use.
        AU_EMAIL_PROTECTION = "E-mail Protection"
        # The OpenSSL friendly name for the "OCSPSigning" extended key use.
        AU_OCSP_SIGNING = "OCSP Signing"
        # The OpenSSL friendly name for the "timeStamping" extended key use.
        AU_TIME_STAMPING = "Time Stamping"

        # An array of the key uses allowed. See the AU_* constants in this class.
        attr_reader :allowed_uses

        # See OpenSSL::X509::Extension#initialize
        def initialize(*args)
          super(*args)

          @allowed_uses = self.value.split(",").map {|use| use.strip}
        end

        # Returns true if the given use is allowed by this extension.
        # @param [string] friendly_use_name One of the AU_* constants in this class.
        def allows?( friendly_use_name )
          @allowed_uses.include?( friendly_use_name )
        end

        def web_server_authentication?
          allows?( AU_WEB_SERVER_AUTH )
        end

        def web_client_authentication?
          allows?( AU_WEB_CLIENT_AUTH )
        end

        def code_signing?
          allows?( AU_CODE_SIGNING )
        end

        def email_protection?
          allows?( AU_EMAIL_PROTECTION )
        end

        def ocsp_signing?
          allows?( AU_OCSP_SIGNING )
        end

        def time_stamping?
          allows?( AU_TIME_STAMPING )
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

        # An array of the DNS alternative names, if any
        attr_reader :dns_names
        # An array of the IP-address alternative names, if any
        attr_reader :ip_addresses
        # An array of the URI alternative names, if any
        attr_reader :uris

        # See OpenSSL::X509::Extension#initialize
        def initialize(*args)
          super(*args)

          @dns_names = self.value.scan( DNS_REGEX ).map { |match| match[0] }
          @ip_addresses = self.value.scan( IP_ADDRESS_REGEX ).map { |match| match[0] }
          @uris = self.value.scan( URI_REGEX ).map { |match| match[0] }
        end
      end

      # Implements the AuthorityInfoAccess certificate extension, with methods to
      # provide access to the components and meaning of the extension's contents.
      class AuthorityInfoAccess < OpenSSL::X509::Extension
        # friendly name for AIA OID
        OID = "authorityInfoAccess"
        Extensions.register_class(self)

        # An array of the OCSP URIs, if any
        attr_reader :ocsp_uris
        # An array of the CA issuers URIs, if any
        attr_reader :ca_issuers_uris

        # See OpenSSL::X509::Extension#initialize
        def initialize(*args)
          super(*args)

          @ocsp_uris = self.value.scan( /OCSP - #{URI_REGEX}/ ).map { |match| match[0] }
          @ca_issuers_uris = self.value.scan( /CA Issuers - #{URI_REGEX}/ ).map { |match| match[0] }
        end
      end

      # Implements the CrlDistributionPoints certificate extension, with methods to
      # provide access to the components and meaning of the extension's contents.
      class CrlDistributionPoints < OpenSSL::X509::Extension
        # friendly name for CDP OID
        OID = "crlDistributionPoints"
        Extensions.register_class(self)

        # An array of the CRL URIs, if any
        attr_reader :crl_uris

        # See OpenSSL::X509::Extension#initialize
        def initialize(*args)
          super(*args)

          @crl_uris = self.value.scan( URI_REGEX ).map { |match| match[0] }
        end
      end

      # Implements the OCSP noCheck certificate extension
      class OCSPNoCheck < OpenSSL::X509::Extension
        OID = "noCheck"
        Extensions.register_class(self)

        # See OpenSSL::X509::Extension#initialize
        def initialize(*args)
          super(*args)
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

