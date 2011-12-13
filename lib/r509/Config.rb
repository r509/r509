require 'yaml'
require 'openssl'
require 'r509/Exceptions'
require 'r509/io_helpers'
require 'fileutils'
require 'pathname'

module R509
    # Provides access to configuration profiles
    class ConfigProfile
        attr_reader :basic_constraints, :key_usage, :extended_key_usage,
          :certificate_policies

        # @option [String] :basic_constraints
        # @option [Array] :key_usage
        # @option [Array] :extended_key_usage
        # @option [Array] :certificate_policies
        def initialize(opts = {})
          @basic_constraints = opts[:basic_constraints]
          @key_usage = opts[:key_usage]
          @extended_key_usage = opts[:extended_key_usage]
          @certificate_policies = opts[:certificate_policies]
        end
    end

    # Stores a configuration for our CA.
    class Config
        include R509::IOHelpers
        extend R509::IOHelpers
        attr_accessor :ca_cert, :crl_validity_hours, :message_digest,
          :cdp_location, :crl_start_skew_seconds, :ocsp_location, :ocsp_chain,
          :ocsp_start_skew_seconds, :ocsp_validity_hours

        # @options opts [R509::Cert] :ca_cert Cert+Key pair
        # @option opts [Integer] :crl_validity_hours (168) The number of hours that
        #  a CRL will be valid. Defaults to 7 days.
        # @option opts [Hash<String, ConfigProfile>] :profiles
        # @option opts [String] :message_digest (SHA1) The hashing algorithm to use.
        # @option opts [String] :cdp_location
        # @option opts [String] :ocsp_location
        # @option opts [Integer] :crl_number (0) The initial CRL number.
        # @option opts [String] :crl_number_file The file that we will save
        #  the CRL numbers to.
        # @option opts [String] :crl_list_file The file that we will save
        #  the CRL list data to.
        # @option opts [R509::Cert] :ocsp_cert An optional cert+key pair
        # OCSP signing delegate
        # @option opts [Array<OpenSSL::X509::Certificate>] :ocsp_chain An optional array
        # that constitutes the chain to attach to an OCSP response
        #
        def initialize(opts = {} )
            if not opts.has_key?(:ca_cert) then
                raise ArgumentError, 'Config object requires that you pass :ca_cert'
            end

            @ca_cert = opts[:ca_cert]

            if not @ca_cert.kind_of?(R509::Cert) then
                raise ArgumentError, ':ca_cert must be of type R509::Cert'
            end
            if not @ca_cert.has_private_key?
                raise ArgumentError, ':ca_cert object must contain a private key, not just a certificate'
            end

            #ocsp data
            if opts.has_key?(:ocsp_cert) and not opts[:ocsp_cert].kind_of(R509::Cert) then
                raise ArgumentError, ':ocsp_cert, if provided, must be of type R509::Cert'
            end
            if opts.has_key?(:ocsp_cert) and not opts[:ocsp_cert].has_private_key?
                raise ArgumentError, ':ocsp_cert must contain a private key, not just a certificate'
            end
            @ocsp_cert = opts[:ocsp_cert]
            @ocsp_location = opts[:ocsp_location]
            @ocsp_chain = opts[:ocsp_chain] if opts[:ocsp_chain].kind_of?(Array)
            @ocsp_validity_hours = opts[:ocsp_validity_hours] || 168
            @ocsp_start_skew_seconds = opts[:ocsp_start_skew_seconds] || 3600

            @crl_validity_hours = opts[:crl_validity_hours] || 168
            @crl_start_skew_seconds = opts[:crl_start_skew_seconds] || 3600
            @cdp_location = opts[:cdp_location]
            @message_digest = opts[:message_digest] || "SHA1"
            @crl_number = opts[:crl_number] || 0

            #the following indicates that we should automatically save the
            #respective files automatically.
            @do_save_crl_number = false
            @do_save_crl_list = false

            if opts.has_key?(:crl_number_file)
                # If this is specified, then it had better not be nil.
                @crl_number_file = opts[:crl_number_file]
                # Now read the number from the file.
                @crl_number = read_data(@crl_number_file).to_i

                @do_save_crl_number = true
            end

            if opts.has_key?(:crl_list_file)
                @crl_list_file = opts[:crl_list_file]
                @do_save_crl_list = true
                load_revoke_crl_list
            else
                @revoked_certs = {}
            end

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

        # @param [String] name The name of the profile
        # @param [ConfigProfile] prof The profile configuration
        def set_profile(name, prof)
            unless prof.is_a?(ConfigProfile)
                raise TypeError, "profile is supposed to be a R509::ConfigProfile"
            end
            @profiles[name] = prof
        end

        # @param [String] prof
        # @return [ConfigProfile] The config profile.
        def profile(prof)
            if !@profiles.has_key?(prof)
                raise R509Error, "unknown profile '#{prof}'"
            end
            @profiles[prof]
        end

        # @return [Integer] the last CRL number
        def crl_number
            @crl_number
        end

        # Increments the crl_number. If you want the changes to be saved, then
        # you must call save_crl_number()
        # @return [Integer] the new CRL number
        #
        def increment_crl_number
            # Have our superclass do the incrementing for us.
            @crl_number += 1
        end

        # Adds a new revoked certificate to our config. If you want to save the
        # changes to the CRL list, then you must call save_crl_list()
        # @param [Integer] serial
        # @param [Integer, nil] reason
        # @param [Integer] revoke_time
        def revoke_cert(serial, reason = nil, revoke_time = Time.now.to_i)
            serial = serial.to_i
            reason = reason.to_i unless reason.nil?
            revoke_time = revoke_time.to_i
            @revoked_certs[serial] = {:reason => reason, :revoke_time => revoke_time}
            nil
        end

        # Unrevokes a certificate, by serial number. If you want to save the
        # changes to the CRL list, then you must call save_crl_list()
        # @param [Integer] serial
        def unrevoke_cert(serial)
            @revoked_certs.delete(serial)
            nil
        end

        # @return [Array<Array>] Returns an array of serial, reason, revoke_time
        #  tuples.
        def revoked_certs
            ret = []
            @revoked_certs.keys.sort.each do |serial|
                ret << [serial, @revoked_certs[serial][:reason], @revoked_certs[serial][:revoke_time]]
            end
            ret
        end

        # @return [Array] serial, reason, revoke_time tuple
        def revoked_cert(serial)
            @revoked_certs[serial]
        end

        # @param [Integer] serial The serial number we want to check
        # @return [Boolean True if the serial number was revoked. False, otherwise.
        def revoked?(serial)
          @revoked_certs.has_key?(serial)
        end

        # Save the CRL number to a filename or IO. If the class was initialized
        # with :crl_number_file, then the filename specified by that will be used
        # by default. If this was not specified, and no filename_or_io was provided,
        # then nothing will be done.
        # @param [String, #write, nil] filename_or_io If provided, the current
        #  crl number will be written to either the file (if a string), or IO. If nil,
        #  then the @crl_number_file will be used. If that is nil, then an error
        #  will be raised.
        def save_crl_number(filename_or_io = @crl_number_file)
            return nil if filename_or_io.nil? && @do_save_crl_number == false

            # No valid filename or IO was specified, so bail.
            if filename_or_io.nil?
                raise R509Error, "No valid CRL number file specified for saving"
            end

            write_data(filename_or_io, self.crl_number.to_s)
            nil
        end

        # Saves the CRL list to a filename or IO. If the class was initialized
        # with :crl_list_file, then the filename specified by that will be used
        # by default. If this was not specified, and no filename_or_io was provided,
        # then nothing will be done.
        # @param [String, #write, nil] filename_or_io If provided, the generated
        #  crl will be written to either the file (if a string), or IO. If nil,
        #  then the @crl_list_file will be used. If that is nil, then an error
        #  will be raised.
        # @raise [R509Error] Raised if there's no @crl_list_file to save to.
        def save_crl_list(filename_or_io = @crl_list_file)
            return nil if filename_or_io.nil? && @do_save_crl_list == false

            # No valid filename or IO was specified, so bail.
            if filename_or_io.nil?
                raise R509Error, "No valid CRL list file specified for saving"
            end

            data = []
            self.revoked_certs.each do |serial, reason, revoke_time|
                data << [serial, revoke_time, reason].join(',')
            end
            write_data(filename_or_io, data.join("\n"))
            nil
        end

        # Loads the revoked CRL list from file.
        # @param [String, #read, nil] filename_or_io If provided, the
        #  crl will be read from either the file (if a string), or IO. If nil,
        #  then the @crl_list_file will be used. If that is nil, then an error
        #  will be raised.
        def load_revoke_crl_list(filename_or_io = @crl_list_file)
            # No valid filename or IO was specified, so bail.
            if filename_or_io.nil?
                raise R509Error, "No valid CRL list file specified for loading"
            end

            @revoked_certs = {}

            data = read_data(filename_or_io)

            data.each_line do |line|
                line.chomp!
                serial,  revoke_time, reason = line.split(',', 3)
                serial = serial.to_i
                reason = (reason == '') ? nil : reason.to_i
                revoke_time = (revoke_time == '') ? nil : revoke_time.to_i
                self.revoke_cert(serial, reason, revoke_time)
            end
            nil
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
            unless conf.kind_of?(::Hash)
                raise ArgumentError, "conf must be a Hash"
            end

            # Duplicate the hash since we will be destroying parts of it.
            conf = conf.dup

            ca_root_path = Pathname.new(opts[:ca_root_path] || FileUtils.getwd)

            unless File.directory?(ca_root_path)
                raise R509Error, "ca_root_path is not a directory: #{ca_root_path}"
            end

            ca_cert_file = ca_root_path + conf.delete('ca_cert')
            ca_key_file = ca_root_path + conf.delete('ca_key')
            ca_cert = R509::Cert.new(
                :cert => read_data(ca_cert_file),
                :key => read_data(ca_key_file)
            )

            opts = {
                :ca_cert => ca_cert,
                :crl_validity_hours => conf.delete('crl_validity_hours'),
                :ocsp_location => conf.delete('ocsp_location'),
                :cdp_location => conf.delete('cdp_location'),
                :message_digest => conf.delete('message_digest'),
            }

            if conf.has_key?("crl_list")
                opts[:crl_list_file] = (ca_root_path + conf.delete('crl_list')).to_s
            end

            if conf.has_key?("crl_number")
                opts[:crl_number_file] = (ca_root_path + conf.delete('crl_number')).to_s
            end

            # Create the instance.
            ret = self.new(opts)

            # The remaining keys should all be profiles :)
            profs = {}
            conf.keys.each do |profile|
                data = conf.delete(profile)
                profs[profile] = ConfigProfile.new(:key_usage => data["key_usage"],
                                                   :extended_key_usage => data["extended_key_usage"],
                                                   :basic_constraints => data["basic_constraints"],
                                                   :certificate_policies => data["certificate_policies"])
            end
            opts[:profiles] = profs

            # Read in revoked certificates.
            ret.load_revoke_crl_list()

            ret
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
        # @param [String] yaml_file The filename to load yaml config data from.
        def self.from_yaml(conf_name, yaml_data, opts = {})
            conf = YAML.load(yaml_data)
            self.load_from_hash(conf[conf_name], opts)
        end
    end
end
