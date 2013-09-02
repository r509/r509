require 'r509/cert/extensions/base'
require 'r509/cert/extensions/validation_mixin'

module R509
  class Cert
    module Extensions
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
        include R509::Cert::Extensions::ValidationMixin
        include R509::Cert::Extensions::GeneralNamesMixin

        # friendly name for CDP OID
        OID = "crlDistributionPoints"
        Extensions.register_class(self)

        # This method takes a hash or an existing Extension object to parse.
        #
        # @option arg :value [Array,R509::ASN1::GeneralNames] Array of hashes (see examples) or GeneralNames object
        # @option arg :critical [Boolean] (false)
        # @example
        #   R509::Cert::Extensions::CRLDistributionPoints.new(
        #     :value => [
        #       { :type => "URI", :value => "http://crl.domain.com/test.crl" }
        #   )
        # @example
        #   name = R509::ASN1::GeneralName.new(:type => "URI", :value => "http://crl.domain.com/test.crl")
        #   R509::Cert::Extensions::CRLDistributionPoints.new(
        #     :value => [name]
        #   )
        def initialize(arg)
          if not R509::Cert::Extensions.is_extension?(arg)
            arg = build_extension(arg)
          end

          super(arg)
          parse_extension
        end

        # @return [Hash]
        def to_h
          {
            :critical => self.critical?,
            :value => R509::Cert::Extensions.names_to_h(@general_names.names)
          }
        end

        # @return [YAML]
        def to_yaml
          self.to_h.to_yaml
        end

        private

        def parse_extension
          @general_names= R509::ASN1::GeneralNames.new
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
            @general_names.add_item(distribution_point.entries[0].value[0].value[0])
          end
        end

        def build_extension(arg)
          validate_crl_distribution_points(arg)
          validate_location('crl_distribution_points',arg[:value])
          serialize = R509::ASN1::GeneralNames.new(arg[:value]).serialize_names
          ef = OpenSSL::X509::ExtensionFactory.new
          ef.config = OpenSSL::Config.parse(serialize[:conf])
          critical = R509::Cert::Extensions.calculate_critical(arg[:critical], false)
          return ef.create_extension("crlDistributionPoints", serialize[:extension_string],critical)
        end

        def validate_crl_distribution_points(arg)
          if not arg.kind_of?(Hash)
            raise ArgumentError, "You must pass a hash with a :value key"
          end
        end
      end
    end
  end
end
