require 'r509/cert/extensions/base'
require 'r509/cert/extensions/validation_mixin'

module R509
  class Cert
    module Extensions
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
        include R509::Cert::Extensions::ValidationMixin

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
        #
        # The following types are known to r509
        #  serverAuth
        #  clientAuth
        #  codeSigning
        #  emailProtection
        #  OCSPSigning
        #  timeStamping
        #  anyExtendedKeyUsage
        #  msCodeInd (not part of RFC 5280)
        #  msCodeCom (not part of RFC 5280)
        #  msCTLSign (not part of RFC 5280)
        #  msSGC (not part of RFC 5280)
        #  msEFS (not part of RFC 5280)
        #  nsSGC (not part of RFC 5280)
        #
        # @option arg :value [Array]
        # @option arg :critical [Boolean] (false)
        # @example
        #   R509::Cert::Extensions::ExtendedKeyUsage.new(
        #     :critical => false,
        #     :value => ['clientAuth,'serverAuth']
        #   )
        def initialize(arg)
          if not R509::Cert::Extensions.is_extension?(arg)
            arg = build_extension(arg)
          end

          super(arg)
          parse_extension
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

        # @return [Hash]
        def to_h
          { :value => @allowed_uses, :critical => self.critical?  }
        end

        # @return [YAML]
        def to_yaml
          self.to_h.to_yaml
        end

        private

        def parse_extension
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

        def build_extension(arg)
          validate_usage(arg)
          ef = OpenSSL::X509::ExtensionFactory.new
          critical = R509::Cert::Extensions.calculate_critical(arg[:critical], false)
          return ef.create_extension("extendedKeyUsage", arg[:value].join(","),critical)
        end
      end
    end
  end
end
