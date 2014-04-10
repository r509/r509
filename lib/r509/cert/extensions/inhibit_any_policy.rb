require 'r509/cert/extensions/base'
require 'r509/cert/extensions/validation_mixin'

module R509
  class Cert
    module Extensions
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
        include R509::Cert::Extensions::ValidationMixin

        # friendly name for CP OID
        OID = "inhibitAnyPolicy"
        Extensions.register_class(self)

        # @return [Integer]
        attr_reader :value

        # This method takes a hash or an existing Extension object to parse
        #
        # @option arg :value [Integer]
        # @option arg :critical [Boolean] (true)
        def initialize(arg)
          unless R509::Cert::Extensions.is_extension?(arg)
            arg = build_extension(arg)
          end

          super(arg)
          parse_extension
        end

        # @return [Hash]
        def to_h
          { :critical => self.critical?, :value => @value }
        end

        # @return [YAML]
        def to_yaml
          self.to_h.to_yaml
        end

        private

        def parse_extension
          #   id-ce-inhibitAnyPolicy OBJECT IDENTIFIER ::=  { id-ce 54 }
          #   InhibitAnyPolicy ::= SkipCerts
          #   SkipCerts ::= INTEGER (0..MAX)
          @value = R509::ASN1.get_extension_payload(self).to_i # returns a non-negative integer
        end

        def build_extension(arg)
          validate_non_negative_integer("Inhibit any policy", arg[:value])
          ef = OpenSSL::X509::ExtensionFactory.new
          critical = R509::Cert::Extensions.calculate_critical(arg[:critical], true)
          # must be set critical per RFC 5280
          return ef.create_extension("inhibitAnyPolicy", arg[:value].to_s, critical)
        end
      end
    end
  end
end
