require 'r509/cert/extensions/base'
require 'r509/cert/extensions/validation_mixin'

module R509
  class Cert
    module Extensions
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
        include R509::Cert::Extensions::ValidationMixin

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
        # @option arg :value [Array]
        # @option arg :critical [Boolean] (false)
        # @example
        #   R509::Cert::Extensions::KeyUsage.new(
        #     :critical => false,
        #     :value => ['digitalSignature,'keyEncipherment']
        #   )
        def initialize(arg)
          if not R509::Cert::Extensions.is_extension?(arg)
            validate_usage(arg)
            ef = OpenSSL::X509::ExtensionFactory.new
            critical = R509::Cert::Extensions.calculate_critical(arg[:critical], false)
            arg = ef.create_extension("keyUsage", arg[:value].join(","),critical)
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

        # @return [Hash]
        def to_h
          {
            :value => @allowed_uses,
            :critical => self.critical?
          }
        end

        # @return [YAML]
        def to_yaml
          self.to_h.to_yaml
        end
      end
    end
  end
end
