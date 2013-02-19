module R509
  class Cert
    module Extensions
      # module for holding certificate policy sub-classes
      module CPObjects
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
            if not data.entries[1].nil?
              @policy_qualifiers = PolicyQualifiers.new
              data.entries[1].each do |pq|
                @policy_qualifiers.parse(pq)
              end
            end
          end
        end

        #   PolicyQualifierInfo ::= SEQUENCE {
        #        policyQualifierId  PolicyQualifierId,
        #        qualifier          ANY DEFINED BY policyQualifierId }
        class PolicyQualifiers
          attr_reader :cps_uris, :user_notices
          def initialize
            @cps_uris = []
            @user_notices = []
          end

          def parse(data)
            oid = data.entries[0].value
            case
            when oid == 'id-qt-cps'
              @cps_uris << data.entries[1].value
            when oid == 'id-qt-unotice'
              @user_notices <<  UserNotice.new(data.entries[1])
            end
          end
        end

        #   UserNotice ::= SEQUENCE {
        #        noticeRef        NoticeReference OPTIONAL,
        #        explicitText     DisplayText OPTIONAL }
        class UserNotice
          attr_reader :notice_reference, :explicit_text
          def initialize(data)
            data.each do |qualifier|
              #if we find another sequence, that's a noticeReference, otherwise it's explicitText
              if qualifier.kind_of?(OpenSSL::ASN1::Sequence)
                @notice_reference = NoticeReference.new(qualifier)
              else
                @explicit_text = qualifier.value
              end

            end if data.respond_to?(:each)
          end
        end

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
                  @notice_numbers << ints.value
                end
              else
                @organization = notice_reference.value
              end
            end
          end
        end
      end
    end
  end
end
