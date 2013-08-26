require 'r509/cert/extensions/base'
require 'r509/cert/extensions/validation_mixin'

module R509
  class Cert
    module Extensions
      # RFC 5280 Description (see: http://www.ietf.org/rfc/rfc5280.txt)
      #
      # The policy constraints extension can be used in certificates issued
      # to CAs.  The policy constraints extension constrains path validation
      # in two ways.  It can be used to prohibit policy mapping or require
      # that each certificate in a path contain an acceptable policy
      # identifier.
      #
      # If the inhibitPolicyMapping field is present, the value indicates the
      # number of additional certificates that may appear in the path before
      # policy mapping is no longer permitted.  For example, a value of one
      # indicates that policy mapping may be processed in certificates issued
      # by the subject of this certificate, but not in additional
      # certificates in the path.
      #
      # If the requireExplicitPolicy field is present, the value of
      # requireExplicitPolicy indicates the number of additional certificates
      # that may appear in the path before an explicit policy is required for
      # the entire path.  When an explicit policy is required, it is
      # necessary for all certificates in the path to contain an acceptable
      # policy identifier in the certificate policies extension.  An
      # acceptable policy identifier is the identifier of a policy required
      # by the user of the certification path or the identifier of a policy
      # that has been declared equivalent through policy mapping.
      #
      # You can use this extension to parse an existing extension for easy access
      # to the contents or create a new one.
      class PolicyConstraints < OpenSSL::X509::Extension
        include R509::Cert::Extensions::ValidationMixin

        # friendly name for CP OID
        OID = "policyConstraints"
        Extensions.register_class(self)

        # @return [Integer,nil]
        attr_reader :require_explicit_policy
        # @return [Integer,nil]
        attr_reader :inhibit_policy_mapping

        # This method takes a hash or an existing Extension object to parse
        #
        # @option arg :require_explicit_policy [Integer]
        # @option arg :inhibit_policy_mapping [Integer]
        # @option arg :critical [Boolean] (true)
        def initialize(arg)
          if not R509::Cert::Extensions.is_extension?(arg)
            arg = build_extension(arg)
          end
          super(arg)

          #   id-ce-policyConstraints OBJECT IDENTIFIER ::=  { id-ce 36 }
          #   PolicyConstraints ::= SEQUENCE {
          #        requireExplicitPolicy           [0] SkipCerts OPTIONAL,
          #        inhibitPolicyMapping            [1] SkipCerts OPTIONAL }
          #
          #   SkipCerts ::= INTEGER (0..MAX)
          data = R509::ASN1.get_extension_payload(self)
          data.each do |pc|
            if pc.tag == 0
              @require_explicit_policy = pc.value.bytes.to_a[0]
            elsif pc.tag == 1
              @inhibit_policy_mapping = pc.value.bytes.to_a[0]
            end
          end
        end

        # @return [Hash]
        def to_h
          hash = {
            :critical => self.critical?
          }
          hash[:require_explicit_policy] = @require_explicit_policy unless @require_explicit_policy.nil?
          hash[:inhibit_policy_mapping] = @inhibit_policy_mapping unless @inhibit_policy_mapping.nil?
          hash
        end

        # @return [YAML]
        def to_yaml
          self.to_h.to_yaml
        end

        private

        # @private
        def build_extension(arg)
          validate_policy_constraints(arg)
          constraints = []
          constraints << "requireExplicitPolicy:#{arg[:require_explicit_policy]}" unless arg[:require_explicit_policy].nil?
          constraints << "inhibitPolicyMapping:#{arg[:inhibit_policy_mapping]}" unless arg[:inhibit_policy_mapping].nil?
          ef = OpenSSL::X509::ExtensionFactory.new
          critical = R509::Cert::Extensions.calculate_critical(arg[:critical], true)
          # must be set critical per RFC 5280
          return ef.create_extension("policyConstraints",constraints.join(","),critical)
        end

        # @private
        def validate_policy_constraints(pc)
          if not pc.nil?
            if not pc.kind_of?(Hash)
              raise ArgumentError, 'Policy constraints must be provided as a hash with at least one of the two allowed keys: :inhibit_policy_mapping and :require_explicit_policy'
            end
            if not pc[:inhibit_policy_mapping].nil?
              ipm = validate_non_negative_integer("inhibit_policy_mapping",pc[:inhibit_policy_mapping])
            end
            if not pc[:require_explicit_policy].nil?
              rep = validate_non_negative_integer("require_explicit_policy",pc[:require_explicit_policy])
            end
            if not ipm and not rep
              raise ArgumentError, 'Policy constraints must have at least one of two keys: :inhibit_policy_mapping and :require_explicit_policy and the value must be non-negative'
            end
          end
          pc
        end
      end
    end
  end
end
