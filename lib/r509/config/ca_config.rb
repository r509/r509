require 'yaml'
require 'openssl'
require 'r509/exceptions'
require 'r509/io_helpers'
require 'r509/subject'
require 'r509/private_key'
require 'r509/engine'
require 'fileutils'
require 'pathname'
require 'r509/config/subject_item_policy'
require 'r509/config/cert_profile'

module R509
  # Module to contain all configuration related classes (e.g. CAConfig, CertProfile, SubjectItemPolicy)
  module Config
    # pool of configs, so we can support multiple CAs from a single config file
    class CAConfigPool
      # @option configs [Hash<String, R509::Config::CAConfig>] the configs to add to the pool
      def initialize(configs)
        @configs = configs
      end

      # get all the config names
      def names
        @configs.keys
      end

      # retrieve a particular config by its name
      def [](name)
        @configs[name]
      end

      # @return a list of all the configs in this pool
      def all
        @configs.values
      end

      # @return [Hash]
      def to_h
        @configs.merge(@configs) { |k,v| v.to_h }
      end

      # @return [YAML]
      def to_yaml
        self.to_h.to_yaml
      end

      # Loads the named configuration config from a yaml string.
      # @param [String] name The name of the config within the file. Note
      #  that a single yaml file can contain more than one configuration.
      # @param [String] yaml_data The filename to load yaml config data from.
      def self.from_yaml(name, yaml_data, opts = {})
        conf = YAML.load(yaml_data)
        configs = {}
        conf[name].each_pair do |ca_name, data|
          configs[ca_name] = R509::Config::CAConfig.load_from_hash(data, opts)
        end
        R509::Config::CAConfigPool.new(configs)
      end
    end

    # Stores a configuration for our CA.
    class CAConfig
      include R509::IOHelpers
      extend R509::IOHelpers
      attr_reader :ca_cert, :crl_validity_hours, :crl_start_skew_seconds,
        :crl_number_file, :crl_list_file, :crl_md,
        :ocsp_chain, :ocsp_start_skew_seconds, :ocsp_validity_hours

      # Default number of seconds to subtract from now when calculating the signing time of an OCSP response
      DEFAULT_OCSP_START_SKEW_SECONDS = 3600
      # Default number of hours an OCSP response should be valid for
      DEFAULT_OCSP_VALIDITY_HOURS = 168
      # Default number of hours a CRL should be valid for
      DEFAULT_CRL_VALIDITY_HOURS = 168
      # Default number of seconds to subtract from now when calculating the signing time of a CRL
      DEFAULT_CRL_START_SKEW_SECONDS = 3600

      # @option opts [R509::Cert] :ca_cert Cert+Key pair
      # @option opts [Integer] :crl_validity_hours (168) The number of hours that
      #  a CRL will be valid. Defaults to 7 days.
      # @option opts [Hash<String, R509::Config::CertProfile>] :profiles
      # @option opts [String] :crl_number_file A file to save the CRL number
      #  into. This is only used if you use the default FileReaderWriter in CRL::Administrator
    # @option opts [String] :crl_md Optional digest for signing CRLs. sha1, sha224, sha256, sha384, sha512, md5. Defaults to R509::MessageDigest::DEFAULT_MD
      # @option opts [String] :crl_list_file A file to serialize revoked certificates into. This
      #  is only used if you use the default FileReaderWriter in CRL::Administrator
      # @option opts [R509::Cert] :ocsp_cert An optional cert+key pair
      #  OCSP signing delegate
      # @option opts [R509::Cert] :crl_cert An optional cert+key pair
      #  CRL signing delegate
      # @option opts [Array<OpenSSL::X509::Certificate>] :ocsp_chain An optional array
      #  that constitutes the chain to attach to an OCSP response
      # @option opts [Integer] :ocsp_validity_hours Number of hours OCSP responses should be valid for
      # @option opts [Integer] :ocsp_start_skew_seconds The number of seconds to subtract from Time.now when calculating the signing time of an OCSP response. This is important to handle bad user clocks.
      # @option opts [Integer] :crl_validity_hours Number of hours CRLs should be valid for
      # @option opts [Integer] :crl_start_skew_seconds The number of seconds to subtract from Time.now when calculating the signing time of a CRL. This is important to handle bad user clocks.
      #
      def initialize(opts = {} )
        if not opts.has_key?(:ca_cert) then
          raise ArgumentError, 'Config object requires that you pass :ca_cert'
        end

        @ca_cert = opts[:ca_cert]

        if not @ca_cert.kind_of?(R509::Cert) then
          raise ArgumentError, ':ca_cert must be of type R509::Cert'
        end

        #ocsp data
        if opts.has_key?(:ocsp_cert)
          check_ocsp_crl_delegate(opts[:ocsp_cert],'ocsp_cert')
          @ocsp_cert = opts[:ocsp_cert]
        end
        @ocsp_chain = opts[:ocsp_chain] if opts[:ocsp_chain].kind_of?(Array)
        @ocsp_validity_hours = opts[:ocsp_validity_hours] || DEFAULT_OCSP_VALIDITY_HOURS
        @ocsp_start_skew_seconds = opts[:ocsp_start_skew_seconds] || DEFAULT_OCSP_START_SKEW_SECONDS

        if opts.has_key?(:crl_cert)
          check_ocsp_crl_delegate(opts[:crl_cert],'crl_cert')
          @crl_cert = opts[:crl_cert]
        end
        @crl_validity_hours = opts[:crl_validity_hours] || DEFAULT_CRL_VALIDITY_HOURS
        @crl_start_skew_seconds = opts[:crl_start_skew_seconds] || DEFAULT_CRL_START_SKEW_SECONDS
        @crl_number_file = opts[:crl_number_file] || nil
        @crl_list_file = opts[:crl_list_file] || nil
        @crl_md = opts[:crl_md] || R509::MessageDigest::DEFAULT_MD



        @profiles = {}
        if opts[:profiles]
          opts[:profiles].each_pair do |name, prof|
            set_profile(name, prof)
          end
        end

      end

      # @return [R509::Cert] either a custom OCSP cert or the ca_cert
      def ocsp_cert
        if @ocsp_cert.nil? then @ca_cert else @ocsp_cert end
      end

      # @return [R509::Cert] either a custom CRL cert or the ca_cert
      def crl_cert
        if @crl_cert.nil? then @ca_cert else @crl_cert end
      end

      # @param [String] name The name of the profile
      # @param [R509::Config::CertProfile] prof The profile configuration
      def set_profile(name, prof)
        unless prof.is_a?(R509::Config::CertProfile)
          raise TypeError, "profile is supposed to be a R509::Config::CertProfile"
        end
        @profiles[name] = prof
      end

      # @param [String] prof
      # @return [R509::Config::CertProfile] The config profile.
      def profile(prof)
        if !@profiles.has_key?(prof)
          raise R509::R509Error, "unknown profile '#{prof}'"
        end
        @profiles[prof]
      end

      # @return [Integer] The number of profiles
      def num_profiles
        @profiles.count
      end

      # @return [Hash]
      def to_h
        hash = {}
        hash["ca_cert"] = build_cert_hash(@ca_cert)
        hash["ocsp_cert"] = build_cert_hash(@ocsp_cert) unless @ocsp_cert.nil?
        hash["crl_cert"] = build_cert_hash(@crl_cert) unless @crl_cert.nil?
        hash["ocsp_chain"] = "<add_path>" unless @ocsp_chain.nil?
        hash["ocsp_start_skew_seconds"] = @ocsp_start_skew_seconds
        hash["ocsp_validity_hours"] = @ocsp_validity_hours
        hash["crl_start_skew_seconds"] = @crl_start_skew_seconds
        hash["crl_validity_hours"] = @crl_validity_hours
        hash["crl_list_file"] = @crl_list_file unless @crl_list_file.nil?
        hash["crl_number_file"] = @crl_number_file unless @crl_number_file.nil?
        hash["crl_md"] = @crl_md
        hash["profiles"] = @profiles.merge(@profiles) { |k,v| v.to_h } unless @profiles.empty?
        hash
      end

      # @return [YAML]
      def to_yaml
        self.to_h.to_yaml
      end

      ######### Class Methods ##########

      # Load the configuration from a data hash. The same type that might be
      # used when loading from a YAML file.
      # @param [Hash] conf A hash containing all the configuration options
      # @option opts [String] :ca_root_path The root path for the CA. Defaults to
      #  the current working directory.
      def self.load_from_hash(conf, opts = {})
        if conf.nil?
          raise ArgumentError, "conf not found"
        end
        unless conf.kind_of?(Hash)
          raise ArgumentError, "conf must be a Hash"
        end

        ca_root_path = Pathname.new(opts[:ca_root_path] || FileUtils.getwd)

        unless File.directory?(ca_root_path)
          raise R509Error, "ca_root_path is not a directory: #{ca_root_path}"
        end

        ca_cert = self.load_ca_cert(conf['ca_cert'],ca_root_path)

        ocsp_cert = self.load_ca_cert(conf['ocsp_cert'],ca_root_path)

        crl_cert = self.load_ca_cert(conf['crl_cert'],ca_root_path)

        ocsp_chain = build_ocsp_chain(conf['ocsp_chain'],ca_root_path)

        opts = {
          :ca_cert => ca_cert,
          :ocsp_cert => ocsp_cert,
          :crl_cert => crl_cert,
          :ocsp_chain => ocsp_chain,
          :crl_validity_hours => conf['crl_validity_hours'],
          :ocsp_validity_hours => conf['ocsp_validity_hours'],
          :ocsp_start_skew_seconds => conf['ocsp_start_skew_seconds'],
          :crl_md => conf['crl_md'],
        }

        if conf.has_key?("crl_list_file")
          opts[:crl_list_file] = (ca_root_path + conf['crl_list_file']).to_s
        end

        if conf.has_key?("crl_number_file")
          opts[:crl_number_file] = (ca_root_path + conf['crl_number_file']).to_s
        end

        opts[:profiles] = self.load_profiles(conf['profiles'])

        # Create the instance.
        self.new(opts)
      end

      # Used by load_from_hash
      #
      # @param profiles [Hash] Hash of profiles
      # @return [Hash] hash of parsed profiles
      def self.load_profiles(profiles)
        profs = {}
        profiles.each do |profile,data|
          if not data["subject_item_policy"].nil?
            subject_item_policy = R509::Config::SubjectItemPolicy.new(data["subject_item_policy"])
          end
          profs[profile] = R509::Config::CertProfile.new(:key_usage => data["key_usage"],
                             :extended_key_usage => data["extended_key_usage"],
                             :basic_constraints => data["basic_constraints"],
                             :certificate_policies => data["certificate_policies"],
                             :ocsp_no_check => data["ocsp_no_check"],
                             :inhibit_any_policy => data["inhibit_any_policy"],
                             :policy_constraints => data["policy_constraints"],
                             :name_constraints => data["name_constraints"],
                             :crl_distribution_points => data["crl_distribution_points"],
                             :authority_info_access => data["authority_info_access"],
                             :default_md => data["default_md"],
                             :allowed_mds => data["allowed_mds"],
                             :subject_item_policy => subject_item_policy)
        end unless profiles.nil?
        profs
      end

      # Loads the named configuration config from a yaml file.
      # @param [String] conf_name The name of the config within the file. Note
      #  that a single yaml file can contain more than one configuration.
      # @param [String] yaml_file The filename to load yaml config data from.
      def self.load_yaml(conf_name, yaml_file, opts = {})
        conf = YAML.load_file(yaml_file)
        self.load_from_hash(conf[conf_name], opts)
      end

      # Loads the named configuration config from a yaml string.
      # @param [String] conf_name The name of the config within the file. Note
      #  that a single yaml file can contain more than one configuration.
      # @param [String] yaml_data The filename to load yaml config data from.
      def self.from_yaml(conf_name, yaml_data, opts = {})
        conf = YAML.load(yaml_data)
        self.load_from_hash(conf[conf_name], opts)
      end

      private

      def build_cert_hash(obj)
        hash = { "cert" => "<add_path>" }
        if not obj.key.nil? and obj.key.in_hardware?
          hash["engine"] = { :so_path => "<add_path>", :id => "<add_name>" }
          return hash
        elsif not obj.key.nil?
          hash["key"] = "<add_path>"
        end
        hash
      end

      def self.load_ca_cert(ca_cert_hash,ca_root_path)
        return nil if ca_cert_hash.nil?
        if ca_cert_hash.has_key?('engine')
          ca_cert = self.load_with_engine(ca_cert_hash,ca_root_path)
        end

        if ca_cert.nil? and ca_cert_hash.has_key?('pkcs12')
          ca_cert = self.load_with_pkcs12(ca_cert_hash,ca_root_path)
        end

        if ca_cert.nil? and ca_cert_hash.has_key?('cert')
          ca_cert = self.load_with_key(ca_cert_hash,ca_root_path)
        end

        return ca_cert
      end

      def self.load_with_engine(ca_cert_hash,ca_root_path)
        if ca_cert_hash.has_key?('key')
          raise ArgumentError, "You can't specify both key and engine"
        end
        if ca_cert_hash.has_key?('pkcs12')
          raise ArgumentError, "You can't specify both engine and pkcs12"
        end
        if not ca_cert_hash.has_key?('key_name')
          raise ArgumentError, "You must supply a key_name with an engine"
        end

        engine = R509::Engine.instance.load(ca_cert_hash['engine'])

        ca_key = R509::PrivateKey.new(
          :engine => engine,
          :key_name => ca_cert_hash['key_name']
        )
        ca_cert_file = ca_root_path + ca_cert_hash['cert']
        ca_cert = R509::Cert.new(
          :cert => read_data(ca_cert_file),
          :key => ca_key
        )
        ca_cert
      end

      def self.load_with_pkcs12(ca_cert_hash,ca_root_path)
        if ca_cert_hash.has_key?('cert')
          raise ArgumentError, "You can't specify both pkcs12 and cert"
        end
        if ca_cert_hash.has_key?('key')
          raise ArgumentError, "You can't specify both pkcs12 and key"
        end

        pkcs12_file = ca_root_path + ca_cert_hash['pkcs12']
        ca_cert = R509::Cert.new(
          :pkcs12 => read_data(pkcs12_file),
          :password => ca_cert_hash['password']
        )
        ca_cert
      end

      def self.load_with_key(ca_cert_hash,ca_root_path)
        ca_cert_file = ca_root_path + ca_cert_hash['cert']

        if ca_cert_hash.has_key?('key')
          ca_key_file = ca_root_path + ca_cert_hash['key']
          ca_key = R509::PrivateKey.new(
            :key => read_data(ca_key_file),
            :password => ca_cert_hash['password']
          )
          ca_cert = R509::Cert.new(
            :cert => read_data(ca_cert_file),
            :key => ca_key
          )
        else
          # in certain cases (OCSP responders for example) we may want
          # to load a ca_cert with no private key
          ca_cert = R509::Cert.new(:cert => read_data(ca_cert_file))
        end
        ca_cert
      end

      def check_ocsp_crl_delegate(cert,kind)
        if not cert.kind_of?(R509::Cert) and not cert.nil?
          raise ArgumentError, ":#{kind}, if provided, must be of type R509::Cert"
        end
        if not cert.nil? and not cert.has_private_key?
          raise ArgumentError, ":#{kind} must contain a private key, not just a certificate"
        end
      end

      def self.build_ocsp_chain(ocsp_chain_path,ca_root_path)
        ocsp_chain = []
        if not ocsp_chain_path.nil?
          ocsp_chain_data = read_data(ca_root_path+ocsp_chain_path)
          cert_regex = /-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/m
          ocsp_chain_data.scan(cert_regex) do |cert|
            ocsp_chain.push(OpenSSL::X509::Certificate.new(cert))
          end
        end
        ocsp_chain
      end

    end
  end
end
