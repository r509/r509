require 'r509/cert/extensions/base'
require 'r509/cert/extensions/validation_mixin'

module R509
  class Cert
    module Extensions
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
        include R509::Cert::Extensions::ValidationMixin
        include R509::Cert::Extensions::GeneralNamesMixin

        # friendly name for SAN OID
        OID = "subjectAltName"
        Extensions.register_class(self)

        # @return [R509::ASN1::GeneralNames]
        attr_reader :general_names

        # This method takes a hash or an existing Extension object to parse
        #
        # @option arg :value [Array,R509::ASN1::GeneralNames] If you supply an Array
        #   it must contain hashes in the standard GeneralName format (:type and :value).
        #   You can also pass a pre-existing GeneralNames object
        # @option arg :critical [Boolean] (false)
        def initialize(arg)
          unless R509::Cert::Extensions.is_extension?(arg)
            arg = build_extension(arg)
          end
          super(arg)
          parse_extension
        end

        # @return [Hash]
        def to_h
          { :critical => self.critical?, :value => @general_names.to_h }
        end

        # @return [YAML]
        def to_yaml
          self.to_h.to_yaml
        end

        private

        def parse_extension
          data = R509::ASN1.get_extension_payload(self)
          @general_names = R509::ASN1::GeneralNames.new
          data.entries.each do |gn|
            @general_names.add_item(gn)
          end
        end

        def build_extension(arg)
          validate_subject_alternative_name(arg)
          serialize = R509::ASN1::GeneralNames.new(arg[:value]).serialize_names
          ef = OpenSSL::X509::ExtensionFactory.new
          ef.config = OpenSSL::Config.parse(serialize[:conf])
          critical = R509::Cert::Extensions.calculate_critical(arg[:critical], false)
          ef.create_extension("subjectAltName", serialize[:extension_string], critical)
        end

        def validate_subject_alternative_name(san)
          if !san.is_a?(Hash) || !(san[:value].is_a?(R509::ASN1::GeneralNames) || san[:value].is_a?(Array))
            raise ArgumentError, "You must supply a hash with a :value"
          end
          validate_general_name_hash_array(san[:value])
        end
      end
    end
  end
end
