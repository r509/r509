require 'r509/cert/extensions/base'
require 'r509/cert/extensions/validation_mixin'

module R509
  class Cert
    module Extensions
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
        include R509::Cert::Extensions::ValidationMixin

        # friendly name for AIA OID
        OID = "authorityInfoAccess"
        Extensions.register_class(self)

        # An R509::ASN1::GeneralNames object of OCSP endpoints (or nil if not present)
        # @return [R509::ASN1::GeneralNames,nil]
        attr_reader :ocsp
        # An R509::ASN1::GeneralNames object of CA Issuers (or nil if not present)
        # @return [R509::ASN1::GeneralNames,nil]
        attr_reader :ca_issuers

        # This method takes a hash or an existing Extension object to parse. If passing
        # a hash you must supply :ocsp_location and/or :ca_issuers_location. These values
        # must be in the form seen in the examples below.
        #
        # @option arg :ocsp_location [Array,R509::ASN1::GeneralNames] Array of hashes (see examples) or GeneralNames object
        # @option arg :ca_issuers_location [Array] Array of hashes (see examples) or GeneralNames object
        # @option arg :critical [Boolean] (false)
        # @example
        #   R509::Cert::Extensions::AuthorityInfoAccess.new(
        #     :ocsp_location => [ { :type => "URI", :value => "http://ocsp.domain.com" } ],
        #     :ca_issuers_location => [ { :type => "dirName", :value => { :CN => 'myCN', :O => 'some Org' } ]
        #   )
        # @example
        #   name = R509::ASN1::GeneralName.new(:type => "IP", :value => "127.0.0.1")
        #   R509::Cert::Extensions::AuthorityInfoAccess.new(
        #     :ca_issuers_location => [name]
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
          hash = { :critical => self.critical? }
          hash[:ocsp_location] = R509::Cert::Extensions.names_to_h(@ocsp.names) unless @ocsp.names.empty?
          hash[:ca_issuers_location] = R509::Cert::Extensions.names_to_h(@ca_issuers.names) unless @ca_issuers.names.empty?
          hash
        end

        # @return [YAML]
        def to_yaml
          self.to_h.to_yaml
        end

        private

        def parse_extension
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

        def build_extension(arg)
          validate_authority_info_access(arg)
          aia = []
          aia_conf = []

          locations = [
            { :key => :ocsp_location, :short_name => 'OCSP' },
            { :key => :ca_issuers_location, :short_name => 'caIssuers' }
          ]

          locations.each do |pair|
            validate_location(pair[:key].to_s,arg[pair[:key]])
            data = arg[pair[:key]]
            if not data.nil?
              elements = R509::ASN1::GeneralNames.new(data)
              elements.names.each do |name|
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

        def validate_authority_info_access(aia)
          if not aia.kind_of?(Hash) or (aia[:ocsp_location].nil? and aia[:ca_issuers_location].nil?)
            raise ArgumentError, "You must pass a hash with at least one of the following two keys (:ocsp_location, :ca_issuers_location)"
          end
        end
      end
    end
  end
end
