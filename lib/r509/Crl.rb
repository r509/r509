require 'openssl'
require 'r509/Config'
require 'r509/Exceptions'
require 'r509/io_helpers'

module R509
    # Used to generate CRLs
    class Crl
        include R509::IOHelpers

        attr_reader :crl_number,:crl_list_file,:crl_number_file, :validity_hours

        # @param [R509::Config::CaConfig]
        def initialize(config)
            @config = config

            unless @config.kind_of?(R509::Config::CaConfig)
                raise R509Error, "config must be a kind of R509::Config::CaConfig"
            end

            @validity_hours = @config.crl_validity_hours
            @start_skew_seconds = @config.crl_start_skew_seconds
            @crl = nil

            @crl_number_file = @config.crl_number_file
            if not @crl_number_file.nil?
                @crl_number = read_data(@crl_number_file).to_i
            else
                @crl_number = 0
            end


            @crl_list_file = @config.crl_list_file
            load_crl_list(@crl_list_file)
        end

        # Indicates whether the serial number has been revoked, or not.
        #
        # @param [Integer] serial The serial number we want to check
        # @return [Boolean] True if the serial number was revoked. False, otherwise.
        def revoked?(serial)
          @revoked_certs.has_key?(serial)
        end

        # @return [Array] serial, reason, revoke_time tuple
        def revoked_cert(serial)
            @revoked_certs[serial]
        end

        # Returns the CRL in PEM format
        #
        # @return [String] the CRL in PEM format
        def to_pem
            @crl.to_pem
        end

        alias :to_s :to_pem

        # Returns the CRL in DER format
        #
        # @return [String] the CRL in DER format
        def to_der
            @crl.to_der
        end

        # Writes the CRL into the PEM format
        #
        # @param [String, #write] filename_or_io Either a string of the path for
        #  the file that you'd like to write, or an IO-like object.
        def write_pem(filename_or_io)
            write_data(filename_or_io, @crl.to_pem)
        end

        # Writes the CRL into the PEM format
        #
        # @param [String, #write] filename_or_io Either a string of the path for
        #  the file that you'd like to write, or an IO-like object.
        def write_der(filename_or_io)
            write_data(filename_or_io, @crl.to_der)
        end

        # Returns the signing time of the CRL
        #
        # @return [Time] when the CRL was signed
        def last_update
            @crl.last_update
        end

        # Returns the next update time for the CRL
        #
        # @return [Time] when it will be updated next
        def next_update
            @crl.next_update
        end

        # Adds a certificate to the revocation list. After calling you must call generate_crl to sign a new CRL
        #
        # @param serial [Integer] serial number of the certificate to revoke
        # @param reason [Integer] reason for revocation
        # @param revoke_time [Integer]
        # @param generate_and_save [Boolean] whether we want to generate the CRL and save its file (default=true)
        #
        #   reason codes defined by rfc 5280
        #
        #   CRLReason ::= ENUMERATED {
        #         unspecified             (0),
        #         keyCompromise           (1),
        #         cACompromise            (2),
        #         affiliationChanged      (3),
        #         superseded              (4),
        #         cessationOfOperation    (5),
        #         certificateHold         (6),
        #         removeFromCRL           (8),
        #         privilegeWithdrawn      (9),
        #         aACompromise           (10) }
        def revoke_cert(serial,reason=nil, revoke_time=Time.now.to_i, generate_and_save=true)
            if not reason.to_i.between?(0,10)
                reason = 0
            end
            serial = serial.to_i
            reason = reason.to_i
            revoke_time = revoke_time.to_i
            if revoked?(serial)
                raise R509::R509Error, "Cannot revoke a previously revoked certificate"
            end
            @revoked_certs[serial] = {:reason => reason, :revoke_time => revoke_time}
            if generate_and_save
                generate_crl()
                save_crl_list()
            end
            nil
        end

        # Remove serial from revocation list. After unrevoking you must call generate_crl to sign a new CRL
        #
        # @param serial [Integer] serial number of the certificate to remove from revocation
        def unrevoke_cert(serial)
            @revoked_certs.delete(serial)
            generate_crl()
            save_crl_list()
            nil
        end

        # Remove serial from revocation list
        #
        # @return [String] PEM encoded signed CRL
        def generate_crl
            crl = OpenSSL::X509::CRL.new
            crl.version = 1
            now = Time.at Time.now.to_i
            crl.last_update = now-@start_skew_seconds
            crl.next_update = now+@validity_hours*3600
            crl.issuer = @config.ca_cert.issuer

            self.revoked_certs.each do |serial, reason, revoke_time|
                revoked = OpenSSL::X509::Revoked.new
                revoked.serial = OpenSSL::BN.new serial.to_s
                revoked.time = Time.at(revoke_time)
                if !reason.nil?
                    enum = OpenSSL::ASN1::Enumerated(reason) #see reason codes below
                    ext = OpenSSL::X509::Extension.new("CRLReason", enum)
                    revoked.add_extension(ext)
                end
                #now add it to the crl
                crl.add_revoked(revoked)
            end

            ef = OpenSSL::X509::ExtensionFactory.new
            ef.issuer_certificate = @config.ca_cert.cert
            ef.crl = crl
            #grab crl number from file, increment, write back
            crl_number = increment_crl_number
            crlnum = OpenSSL::ASN1::Integer(crl_number)
            crl.add_extension(OpenSSL::X509::Extension.new("crlNumber", crlnum))
            extensions = []
            extensions << ["authorityKeyIdentifier", "keyid:always,issuer:always", false]
            extensions.each{|oid, value, critical|
                crl.add_extension(ef.create_extension(oid, value, critical))
            }
            crl.sign(@config.ca_cert.key.key, OpenSSL::Digest::SHA1.new)
            @crl = crl
            @crl.to_pem
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

        # Saves the CRL list to a filename or IO. If the class was initialized
        # with :crl_list_file, then the filename specified by that will be used
        # by default.
        # @param [String, #write, nil] filename_or_io If provided, the generated
        #  crl will be written to either the file (if a string), or IO. If nil,
        #  then the @crl_list_file will be used. If that is nil, then an error
        #  will be raised.
        def save_crl_list(filename_or_io = @crl_list_file)
            return nil if filename_or_io.nil?

            data = []
            self.revoked_certs.each do |serial, reason, revoke_time|
                data << [serial, revoke_time, reason].join(',')
            end
            write_data(filename_or_io, data.join("\n"))
            nil
        end

        # Save the CRL number to a filename or IO. If the class was initialized
        # with :crl_number_file, then the filename specified by that will be used
        # by default.
        # @param [String, #write, nil] filename_or_io If provided, the current
        #  crl number will be written to either the file (if a string), or IO. If nil,
        #  then the @crl_number_file will be used. If that is nil, then an error
        #  will be raised.
        def save_crl_number(filename_or_io = @crl_number_file)
            return nil if filename_or_io.nil?
            # No valid filename or IO was specified, so bail.

            write_data(filename_or_io, self.crl_number.to_s)
            nil
        end

        private

        # Increments the crl_number.
        # @return [Integer] the new CRL number
        #
        def increment_crl_number
            @crl_number += 1
            save_crl_number()
            @crl_number
        end

        # Loads the certificate revocation list from file.
        # @param [String, #read, nil] filename_or_io The
        #  crl will be read from either the file (if a string), or IO.
        def load_crl_list(filename_or_io)
            @revoked_certs = {}

            if filename_or_io.nil?
                generate_crl
                return nil
            end

            data = read_data(filename_or_io)

            data.each_line do |line|
                line.chomp!
                serial,  revoke_time, reason = line.split(',', 3)
                serial = serial.to_i
                reason = (reason == '') ? nil : reason.to_i
                revoke_time = (revoke_time == '') ? nil : revoke_time.to_i
                self.revoke_cert(serial, reason, revoke_time, false)
            end
            generate_crl
            save_crl_list
            nil
        end

    end
end

