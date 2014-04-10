require 'yaml'
require 'openssl'
require 'r509/exceptions'
require 'r509/io_helpers'
require 'r509/subject'
require 'r509/private_key'
require 'r509/engine'
require 'fileutils'
require 'pathname'

module R509
  # Module to contain all configuration related classes (e.g. CAConfig, CertProfile, SubjectItemPolicy)
  module Config
    # Provides access to configuration profiles
    class CertProfile
      attr_reader :basic_constraints, :key_usage, :extended_key_usage,
                  :certificate_policies, :subject_item_policy, :ocsp_no_check,
                  :inhibit_any_policy, :policy_constraints, :name_constraints,
                  :authority_info_access, :crl_distribution_points,
                  :default_md, :allowed_mds

      # All hash options for CertProfile are optional.
      # @option opts [Hash] :basic_constraints
      # @option opts [Hash] :key_usage
      # @option opts [Hash] :extended_key_usage
      # @option opts [Hash] :certificate_policies
      # @option opts [Boolean] :ocsp_no_check Sets OCSP No Check extension in the certificate if true
      # @option opts [Hash] :inhibit_any_policy Sets the value of the inhibitAnyPolicy extension
      # @option opts [Hash] :policy_constraints Sets the value of the policyConstraints extension
      # @option opts [Hash] :authority_info_access
      # @option opts [Hash] :crl_distribution_points
      # @option opts [Hash] :name_constraints Sets the value of the nameConstraints extension
      # @option opts [R509::Config::SubjectItemPolicy] :subject_item_policy
      # @option opts [String] :default_md (SHA1) The hashing algorithm to use.
      # @option opts [Array] :allowed_mds (nil) Array of allowed hashes.
      #  default_md will be automatically added to this list if it isn't already listed.
      def initialize(opts = {})
        @basic_constraints = R509::Cert::Extensions::BasicConstraints.new(opts[:basic_constraints]) unless opts[:basic_constraints].nil?
        @key_usage = R509::Cert::Extensions::KeyUsage.new(opts[:key_usage]) unless opts[:key_usage].nil?
        @extended_key_usage = R509::Cert::Extensions::ExtendedKeyUsage.new(opts[:extended_key_usage]) unless opts[:extended_key_usage].nil?
        @certificate_policies = R509::Cert::Extensions::CertificatePolicies.new(opts[:certificate_policies]) unless opts[:certificate_policies].nil?
        @inhibit_any_policy = R509::Cert::Extensions::InhibitAnyPolicy.new(opts[:inhibit_any_policy]) unless opts[:inhibit_any_policy].nil?
        @policy_constraints = R509::Cert::Extensions::PolicyConstraints.new(opts[:policy_constraints]) unless opts[:policy_constraints].nil?
        @name_constraints = R509::Cert::Extensions::NameConstraints.new(opts[:name_constraints]) unless opts[:name_constraints].nil?
        @ocsp_no_check = R509::Cert::Extensions::OCSPNoCheck.new(opts[:ocsp_no_check]) unless opts[:ocsp_no_check].nil?
        @authority_info_access = R509::Cert::Extensions::AuthorityInfoAccess.new(opts[:authority_info_access]) unless opts[:authority_info_access].nil?
        @crl_distribution_points = R509::Cert::Extensions::CRLDistributionPoints.new(opts[:crl_distribution_points]) unless opts[:crl_distribution_points].nil?
        @subject_item_policy = validate_subject_item_policy(opts[:subject_item_policy])
        @default_md = validate_md(opts[:default_md] || R509::MessageDigest::DEFAULT_MD)
        @allowed_mds = validate_allowed_mds(opts[:allowed_mds])
      end

      # @return [Hash]
      def to_h
        hash = {}
        hash["basic_constraints"] = @basic_constraints.to_h unless @basic_constraints.nil?
        hash["key_usage"] = @key_usage.to_h unless @key_usage.nil?
        hash["extended_key_usage"] = @extended_key_usage.to_h unless @extended_key_usage.nil?
        hash["certificate_policies"] = @certificate_policies.to_h unless @certificate_policies.nil?
        hash["inhibit_any_policy"] = @inhibit_any_policy.to_h unless @inhibit_any_policy.nil?
        hash["policy_constraints"] = @policy_constraints.to_h unless @policy_constraints.nil?
        hash["name_constraints"] = @name_constraints.to_h unless @name_constraints.nil?
        hash["ocsp_no_check"] = @ocsp_no_check.to_h unless @ocsp_no_check.nil?
        hash["authority_info_access"] = @authority_info_access.to_h unless @authority_info_access.nil?
        hash["crl_distribution_points"] = @crl_distribution_points.to_h unless @crl_distribution_points.nil?
        hash["subject_item_policy"] = @subject_item_policy.to_h unless @subject_item_policy.nil?
        hash["default_md"] = @default_md unless @default_md.nil?
        hash["allowed_mds"] = @allowed_mds unless @allowed_mds.nil?
        hash
      end

      # @return [YAML]
      def to_yaml
        self.to_h.to_yaml
      end

      private

      # @private
      def validate_allowed_mds(allowed_mds)
        if allowed_mds.respond_to?(:each)
          allowed_mds = allowed_mds.map { |md| validate_md(md) }
          # case insensitively check if the default_md is in the allowed_mds
          # and add it if it's not there.
          unless allowed_mds.any? { |s| s.casecmp(@default_md) == 0 }
            allowed_mds.push @default_md
          end
        end
        allowed_mds
      end

      # @private
      def validate_md(md)
        md = md.upcase
        unless R509::MessageDigest::KNOWN_MDS.include?(md)
          raise ArgumentError, "An unknown message digest was supplied. Permitted: #{R509::MessageDigest::KNOWN_MDS.join(", ")}"
        end
        md
      end

      # @private
      # validates subject item policy
      def validate_subject_item_policy(sip)
        if not sip.nil? and not sip.kind_of?(R509::Config::SubjectItemPolicy)
          raise ArgumentError, "subject_item_policy must be of type R509::Config::SubjectItemPolicy"
        end
        sip
      end
    end
  end
end
