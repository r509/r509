require 'openssl'
require 'r509/config'
require 'r509/exceptions'
require 'r509/io_helpers'

module R509
  # contains CRL related classes (generator and a pre-existing list loader)
  module CRL
    # Parses CRLs
    class SignedList
      include R509::IOHelpers

      attr_reader :crl, :issuer

      # @param [String,OpenSSL::X509::CRL] crl
      def initialize(crl)
        @crl = OpenSSL::X509::CRL.new(crl)
        @issuer = R509::Subject.new(@crl.issuer)
      end

      # Helper method to quickly load a CRL from the filesystem
      #
      # @param [String] filename Path to file you want to load
      # @return [R509::CRL::SignedList] CRL object
      def self.load_from_file( filename )
        return R509::CRL::SignedList.new( IOHelpers.read_data(filename) )
      end

      # @return [String]
      def signature_algorithm
        @crl.signature_algorithm
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

      # Pass a public key to verify that the CRL is signed by a specific certificate (call cert.public_key on that object)
      #
      # @param [OpenSSL::PKey::PKey] public_key
      # @return [Boolean]
      def verify(public_key)
        @crl.verify(public_key)
      end

      # @param [Integer] serial number
      # @return [Boolean]
      def revoked?(serial)
        if @crl.revoked.find { |revoked| revoked.serial == serial.to_i }
          true
        else
          false
        end
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

      # @return [Hash] hash of serial => { :time, :reason } hashes
      def revoked
        revoked_list = {}
        @crl.revoked.each do |revoked|
          reason = get_reason(revoked)
          revoked_list[revoked.serial.to_i] = { :time => revoked.time, :reason => reason }
        end

        revoked_list
      end

      # @param [Integer] serial number
      # @return [Hash] hash with :time and :reason
      def revoked_cert(serial)
        revoked = @crl.revoked.find { |r| r.serial == serial }
        if revoked
          reason = get_reason(revoked)
          { :time => revoked.time, :reason => reason }
        else
          nil
        end
      end

      private
      def get_reason(revocation_object)
        reason = nil
        revocation_object.extensions.each do |extension|
          if extension.oid == "CRLReason"
            reason = extension.value
          end
        end

        reason
      end
    end

    # Used to manage revocations and generate CRLs
    class Administrator
      include R509::IOHelpers

      attr_reader :crl_number,:crl_list_file,:crl_number_file, :validity_hours, :crl

      # @param [R509::Config::CAConfig] config
      def initialize(config)
        @config = config

        unless @config.kind_of?(R509::Config::CAConfig)
          raise R509Error, "config must be a kind of R509::Config::CAConfig"
        end

        @validity_hours = @config.crl_validity_hours
        @start_skew_seconds = @config.crl_start_skew_seconds
        @crl_md = R509::MessageDigest.new(@config.crl_md)
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
        @revoked_certs.has_key?(serial.to_i)
      end

      # @return [Array] serial, reason, revoke_time tuple
      def revoked_cert(serial)
        @revoked_certs[serial]
      end

      # Adds a certificate to the revocation list. After calling you must call generate_crl to sign a new CRL
      #
      # @param serial [Integer] serial number of the certificate to revoke
      # @param reason [Integer] reason for revocation
      # @param revoke_time [Integer]
      # @param generate_and_save [Boolean] whether we want to generate the CRL and save its file
      #
      # reason codes defined by rfc 5280
      #
      # CRLReason ::= ENUMERATED {
      #     unspecified       (0),
      #     keyCompromise       (1),
      #     cACompromise        (2),
      #     affiliationChanged    (3),
      #     superseded        (4),
      #     cessationOfOperation    (5),
      #     certificateHold     (6),
      #     removeFromCRL       (8),
      #     privilegeWithdrawn    (9),
      #     aACompromise       (10) }
      def revoke_cert(serial,reason=nil, revoke_time=Time.now.to_i, generate_and_save=true)
        if not reason.nil?
          if not reason.kind_of?(Integer) or not reason.between?(0,10) or reason == 7
            raise ArgumentError, "Revocation reason must be integer 0-10 (excluding 7) or nil"
          end
        end

        serial = serial.to_i
        revoke_time = revoke_time.to_i
        if revoked?(serial)
          raise R509::R509Error, "Cannot revoke a previously revoked certificate"
        end
        @revoked_certs[serial] = {:reason => reason, :revoke_time => revoke_time}
        if generate_and_save
          generate_crl
          save_crl_list
        end
        nil
      end

      # Remove serial from revocation list. After unrevoking you must call generate_crl to sign a new CRL
      #
      # @param serial [Integer] serial number of the certificate to remove from revocation
      def unrevoke_cert(serial)
        @revoked_certs.delete(serial)
        generate_crl
        save_crl_list
        nil
      end

      # Generate the CRL
      # @param last_update [Time] the lastUpdate for the CRL
      # @param next_update [Time] the nextUpdate for the CRL
      #
      # @return [String] PEM encoded signed CRL
      def generate_crl(last_update=Time.at(Time.now.to_i)-@start_skew_seconds,next_update=Time.at(Time.now)+@validity_hours*3600)
        # Time.at(Time.now.to_i) removes sub-second precision. Subsecond precision is irrelevant
        # for CRL update times and makes testing harder.
        crl = OpenSSL::X509::CRL.new
        crl.version = 1
        crl.last_update = last_update
        crl.next_update = next_update
        crl.issuer = @config.crl_cert.subject.name

        self.revoked_certs.each do |serial, reason, revoke_time|
          revoked = OpenSSL::X509::Revoked.new
          revoked.serial = OpenSSL::BN.new serial.to_s
          revoked.time = Time.at(revoke_time)
          if not reason.nil?
            enum = OpenSSL::ASN1::Enumerated(reason) #see reason codes below
            ext = OpenSSL::X509::Extension.new("CRLReason", enum)
            revoked.add_extension(ext)
          end
          #now add it to the crl
          crl.add_revoked(revoked)
        end

        ef = OpenSSL::X509::ExtensionFactory.new
        ef.issuer_certificate = @config.crl_cert.cert
        ef.crl = crl
        #grab crl number from file, increment, write back
        crl_number = increment_crl_number
        crlnum = OpenSSL::ASN1::Integer(crl_number)
        crl.add_extension(OpenSSL::X509::Extension.new("crlNumber", crlnum))
        extensions = []
        extensions << ["authorityKeyIdentifier", "keyid", false]
        extensions.each{|oid, value, critical|
          crl.add_extension(ef.create_extension(oid, value, critical))
        }
        crl.sign(@config.crl_cert.key.key, @crl_md.digest)
        @crl = R509::CRL::SignedList.new crl
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
        save_crl_number
        @crl_number
      end

      # Loads the certificate revocation list from file.
      # @param [String, #read, nil] filename_or_io The
      #  crl will be read from either the file (if a string), or IO.
      def load_crl_list(filename_or_io)
        @revoked_certs = {}

        if filename_or_io.nil?
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
        nil
      end

    end
  end
end

