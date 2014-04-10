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
        # friendly name for CP OID
        OID = "certificatePolicies"
        Extensions.register_class(self)
        # @return [Array] Array of R509::Cert::Extensions::PolicyObjects::PolicyInformation objects
        attr_reader :policies

        # This method takes a hash or an existing Extension object to parse. The hash must contain
        # a :value that is an array of policy information. See the example.
        #
        # @option arg :value [Array] Array of hashes in the format shown in the examples. This is a complex hash.
        # @option arg :critical [Boolean] (false)
        # @example
        #  R509::Cert::Extensions::CertificatePolicies.new(:value => [
        #    { :policy_identifier => "2.16.840.1.12345.1.2.3.4.1",
        #      :cps_uris => ["http://example.com/cps","http://other.com/cps"],
        #      :user_notices => [ {:explicit_text => "thing", :organization => "my org", :notice_numbers => [1,2,3,4]} ]
        #   }
        #  ])
        def initialize(arg)
          unless R509::Cert::Extensions.is_extension?(arg)
            arg = build_extension(arg)
          end

          super(arg)
          parse_extension
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

        def parse_extension
          @policies = []
          data = R509::ASN1.get_extension_payload(self)

          # each element of this sequence should be part of a policy + qualifiers
          #   certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
          data.each do |cp|
            @policies << PolicyInformation.new(cp)
          end if data.respond_to?(:each)
        end

        def build_extension(arg)
          validate_certificate_policies(arg[:value])
          conf = []
          policy_names = ["ia5org"]
          arg[:value].each_with_index do |policy, i|
            conf << build_conf("certPolicies#{i}", policy, i)
            policy_names << "@certPolicies#{i}"
          end
          ef = OpenSSL::X509::ExtensionFactory.new
          ef.config = OpenSSL::Config.parse(conf.join("\n"))
          critical = R509::Cert::Extensions.calculate_critical(arg[:critical], false)
          return ef.create_extension("certificatePolicies", policy_names.join(","), critical)
        end

        def build_conf(section, hash, index)
          conf = ["[#{section}]"]
          conf.push "policyIdentifier=#{hash[:policy_identifier]}" unless hash[:policy_identifier].nil?
          hash[:cps_uris].each_with_index do |cps, idx|
            conf.push "CPS.#{idx + 1}=\"#{cps}\""
          end if hash[:cps_uris].respond_to?(:each_with_index)

          user_notice_confs = []
          hash[:user_notices].each_with_index do |un, k|
            conf.push "userNotice.#{k + 1}=@user_notice#{k + 1}#{index}"
            user_notice_confs.push "[user_notice#{k + 1}#{index}]"
            user_notice_confs.push "explicitText=\"#{un[:explicit_text]}\"" unless un[:explicit_text].nil?
            # if org is supplied notice numbers is also required (and vice versa). enforced in CAProfile
            user_notice_confs.push "organization=\"#{un[:organization]}\"" unless un[:organization].nil?
            user_notice_confs.push "noticeNumbers=\"#{un[:notice_numbers].join(",")}\"" unless un[:notice_numbers].nil?
          end if hash[:user_notices].kind_of?(Array)

          conf.concat(user_notice_confs)
          conf.join "\n"
        end

        # validates the structure of the certificate policies array
        def validate_certificate_policies(policies)
          raise ArgumentError, "Not a valid certificate policy structure. Must be an array of hashes" unless policies.kind_of?(Array)

          policies.each do |policy|
            raise ArgumentError, "Each policy requires a policy identifier" if policy[:policy_identifier].nil?
            raise ArgumentError, "CPS URIs must be an array of strings" if not policy[:cps_uris].nil? and not policy[:cps_uris].respond_to?(:each)
            unless policy[:user_notices].nil?
              raise ArgumentError, "User notices must be an array of hashes" unless policy[:user_notices].respond_to?(:each)
              policy[:user_notices].each do |un|
                raise ArgumentError, "If you provide an organization you must provide notice numbers" if not un[:organization].nil? and un[:notice_numbers].nil?
                raise ArgumentError, "If you provide notice numbers you must provide an organization" if not un[:notice_numbers].nil? and un[:organization].nil?
              end
            end
          end
        end
      end

      # This class is used to help build the certificate policies extension
      #   PolicyInformation ::= SEQUENCE {
      #        policyIdentifier   CertPolicyId,
      #        policyQualifiers   SEQUENCE SIZE (1..MAX) OF
      #                                PolicyQualifierInfo OPTIONAL }
      class PolicyInformation
        attr_reader :policy_identifier, :policy_qualifiers
        def initialize(data)
          # store the policy identifier OID
          @policy_identifier = data.entries[0].value
          # iterate the policy qualifiers if any exist
          unless data.entries[1].nil?
            @policy_qualifiers = PolicyQualifiers.new
            data.entries[1].each do |pq|
              @policy_qualifiers.parse(pq)
            end
          end
        end

        # @return [Hash]
        def to_h
          hash = {}
          hash[:policy_identifier] = @policy_identifier
          hash.merge!(@policy_qualifiers.to_h) unless @policy_qualifiers.nil?
          hash
        end

        # @return [YAML]
        def to_yaml
          self.to_h.to_yaml
        end
      end

      # This class is used to help build the certificate policies extension
      #   PolicyQualifierInfo ::= SEQUENCE {
      #        policyQualifierId  PolicyQualifierId,
      #        qualifier          ANY DEFINED BY policyQualifierId }
      class PolicyQualifiers
        attr_reader :cps_uris, :user_notices
        def initialize
          @cps_uris = []
          @user_notices = []
        end

        # parse each PolicyQualifier and store the results into the object array
        def parse(data)
          oid = data.entries[0].value
          case
          when oid == 'id-qt-cps'
            # by RFC definition must be URIs
            @cps_uris << data.entries[1].value
          when oid == 'id-qt-unotice'
            @user_notices <<  UserNotice.new(data.entries[1])
          end
        end

        # @return [Hash]
        def to_h
          hash = {}
          hash[:cps_uris] = @cps_uris
          hash[:user_notices] = @user_notices.map { |notice| notice.to_h } unless @user_notices.empty?
          hash
        end

        # @return [YAML]
        def to_yaml
          self.to_h.to_yaml
        end
      end

      # This class is used to help build the certificate policies extension
      #   UserNotice ::= SEQUENCE {
      #        noticeRef        NoticeReference OPTIONAL,
      #        explicitText     DisplayText OPTIONAL }
      class UserNotice
        attr_reader :notice_reference, :explicit_text
        def initialize(data)
          data.each do |qualifier|
            # if we find another sequence, that's a noticeReference, otherwise it's explicitText
            if qualifier.kind_of?(OpenSSL::ASN1::Sequence)
              @notice_reference = NoticeReference.new(qualifier)
            else
              @explicit_text = qualifier.value
            end

          end if data.respond_to?(:each)
        end

        # @return [Hash]
        def to_h
          hash = {}
          hash[:explicit_text] = @explicit_text unless @explicit_text.nil?
          hash.merge!(@notice_reference.to_h) unless @notice_reference.nil?
          hash
        end

        # @return [YAML]
        def to_yaml
          self.to_h.to_yaml
        end
      end

      # This class is used to help build the certificate policies extension
      #   NoticeReference ::= SEQUENCE {
      #        organization     DisplayText,
      #        noticeNumbers    SEQUENCE OF INTEGER }
      class NoticeReference
        attr_reader :organization, :notice_numbers
        def initialize(data)
          data.each do |notice_reference|
            # if it's displaytext then it's the organization
            # if it's YET ANOTHER ASN1::Sequence, then it's noticeNumbers
            if notice_reference.kind_of?(OpenSSL::ASN1::Sequence)
              @notice_numbers = []
              notice_reference.each do |ints|
                @notice_numbers << ints.value.to_i
              end
            else
              @organization = notice_reference.value
            end
          end
        end

        # @return [Hash]
        def to_h
          hash = {}
          hash[:organization] = @organization unless @organization.nil?
          hash[:notice_numbers] = @notice_numbers unless @notice_numbers.empty?
          hash
        end

        # @return [YAML]
        def to_yaml
          self.to_h.to_yaml
        end
      end
    end
  end
end
