require 'yaml'
require 'openssl'
require 'r509/exceptions'
require 'r509/io_helpers'
require 'r509/subject'
require 'r509/private_key'
require 'r509/engine'
require 'fileutils'
require 'pathname'
require 'r509/validation_mixin'

module R509
  # Module to contain all configuration related classes (e.g. CAConfig, CertProfile, SubjectItemPolicy)
  module Config
    # Provides access to configuration profiles
    class CertProfile
      include R509::ValidationMixin

      attr_reader :basic_constraints, :key_usage, :extended_key_usage,
        :certificate_policies, :subject_item_policy, :ocsp_no_check,
        :inhibit_any_policy, :policy_constraints, :name_constraints,
        :ocsp_location, :cdp_location, :ca_issuers_location, :default_md,
        :allowed_mds

      # All hash options for CertProfile are optional.
      # @option opts [Hash] :basic_constraints
      # @option opts [Array] :key_usage
      # @option opts [Array] :extended_key_usage
      # @option opts [Array] :certificate_policies
      # @option opts [Boolean] :ocsp_no_check Sets OCSP No Check extension in the certificate if true
      # @option opts [Integer] :inhibit_any_policy Sets the value of the inhibitAnyPolicy extension
      # @option opts [Hash] :policy_constraints Sets the value of the policyConstriants extension
      # @option opts [Hash] :name_constraints Sets the value of the nameConstraints extension
      # @option opts [R509::Config::SubjectItemPolicy] :subject_item_policy
      # @option opts [String] :default_md (SHA1) The hashing algorithm to use.
      # @option opts [Array] :allowed_mds (nil) Array of allowed hashes.
      #  default_md will be automatically added to this list if it isn't already listed.
      # @option opts [Array,R509::ASN1::GeneralNames] :cdp_location
      # @option opts [Array,R509::ASN1::GeneralNames] :ocsp_location
      # @option opts [Array,R509::ASN1::GeneralNames] :ca_issuers_location
      def initialize(opts = {})
        @basic_constraints = validate_basic_constraints opts[:basic_constraints]
        @key_usage = validate_key_usage opts[:key_usage]
        @extended_key_usage = validate_extended_key_usage opts[:extended_key_usage]
        @certificate_policies = validate_certificate_policies opts[:certificate_policies]
        @inhibit_any_policy = validate_inhibit_any_policy opts[:inhibit_any_policy]
        @policy_constraints = validate_policy_constraints opts[:policy_constraints]
        @name_constraints = validate_name_constraints opts[:name_constraints]
        @ocsp_no_check = (opts[:ocsp_no_check] == true or opts[:ocsp_no_check] == "true")?true:false
        @subject_item_policy = validate_subject_item_policy opts[:subject_item_policy]
        @ocsp_location = validate_ocsp_location(opts[:ocsp_location])
        @ca_issuers_location = validate_ca_issuers_location(opts[:ca_issuers_location])
        @cdp_location = validate_cdp_location(opts[:cdp_location])
        @default_md = validate_md(opts[:default_md] || R509::MessageDigest::DEFAULT_MD)
        @allowed_mds = validate_allowed_mds(opts[:allowed_mds])
      end

    end

  end
end
