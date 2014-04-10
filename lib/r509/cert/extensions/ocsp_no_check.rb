require 'r509/cert/extensions/base'

module R509
  class Cert
    module Extensions
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
        # friendly name for OCSP No Check
        OID = "noCheck"
        Extensions.register_class(self)

        # This method takes a hash or an existing Extension object to parse
        #
        # @option arg :ocsp_no_check [Any] Pass any value. It's irrelevant.
        # @option arg :critical [Boolean] (false)
        def initialize(arg)
          unless R509::Cert::Extensions.is_extension?(arg)
            arg = build_extension(arg)
          end
          super(arg)
        end

        # @return [Hash]
        def to_h
          { :critical => self.critical?  }
        end

        # @return [YAML]
        def to_yaml
          self.to_h.to_yaml
        end

        private

        def build_extension(arg)
          ef = OpenSSL::X509::ExtensionFactory.new
          critical = R509::Cert::Extensions.calculate_critical(arg[:critical], false)
          return ef.create_extension("noCheck", "yes", critical)
        end
      end
    end
  end
end
