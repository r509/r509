require 'r509/cert/extensions/base'

module R509
  class Cert
    module Extensions
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
          if not R509::Cert::Extensions.is_extension?(arg)
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

        def validate_authority_key_identifier(aki)
          if aki[:value].downcase.include?("keyid") and aki[:public_key].nil?
            raise ArgumentError, "You must supply an OpenSSL::PKey object to :public_key if aki value contains keyid (present by default)"
          end
          if aki[:value].downcase.include?("issuer") and not aki[:issuer_subject].kind_of?(R509::Subject)
            raise ArgumentError, "You must supply an R509::Subject object to :issuer_subject if aki value contains issuer"
          end
          aki
        end
      end
    end
  end
end
