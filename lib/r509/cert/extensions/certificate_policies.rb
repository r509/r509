require 'r509/cert/extensions/base'

module R509
  class Cert
    module Extensions
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
        # @option arg :value [Array] Array of hashes in the same format as passed to R509::Config::CertProfile for certificate policies
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

        # @return [Hash]
        def to_h
          {
            :critical => self.critical?,
            :value => @policies.map { |policy| policy.to_h }
          }
        end

        # @return [YAML]
        def to_yaml
          self.to_h.to_yaml
        end

        private

        # @private
        def build_extension(arg)
          validate_certificate_policies(arg[:value])
          conf = []
          policy_names = ["ia5org"]
          arg[:value].each_with_index do |policy,i|
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
            user_notice_confs.push "noticeNumbers=\"#{un[:notice_numbers].join(",")}\"" unless un[:notice_numbers].nil?
          end unless not hash[:user_notices].kind_of?(Array)

          conf.concat(user_notice_confs)
          conf.join "\n"
        end
      end
    end
  end
end
