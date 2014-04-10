require 'openssl'
require 'r509/config'
require 'r509/exceptions'
require 'r509/io_helpers'

module R509
  # contains CRL related classes (generator and a pre-existing list loader)
  module CRL
    # Used to manage revocations and generate CRLs
    class Administrator
      include R509::IOHelpers

      attr_reader :crl_number, :config

      # @param config [R509::Config::CAConfig]
      # @param reader_writer [R509::CRL::ReaderWriter] A subclass off the R509::CRL::ReaderWriter. Defaults to an instance of R509::CRL::FileReaderWriter.
      def initialize(config,reader_writer=R509::CRL::FileReaderWriter.new)
        @config = config
        unless @config.kind_of?(R509::Config::CAConfig)
          raise R509Error, "config must be a kind of R509::Config::CAConfig"
        end

        if not reader_writer.kind_of?(R509::CRL::ReaderWriter)
          raise ArgumentError, "argument reader_writer must be a subclass of R509::CRL::ReaderWriter"
        end
        @rw = reader_writer
        @rw.crl_list_file = @config.crl_list_file unless not @rw.respond_to?(:crl_list_file=)
        @rw.crl_number_file = @config.crl_number_file unless not @rw.respond_to?(:crl_number_file=)
        @crl_number = @rw.read_number
        @revoked_certs = {}
        @rw.read_list do |serial, reason, revoke_time|
          revoke_cert(serial, reason, revoke_time, false)
        end

        @crl_md = R509::MessageDigest.new(@config.crl_md)
      end

      # Indicates whether the serial number has been revoked, or not.
      #
      # @param [Integer] serial The serial number we want to check
      # @return [Boolean] True if the serial number was revoked. False, otherwise.
      def revoked?(serial)
        @revoked_certs.key?(serial.to_i)
      end

      # @return [Array] serial, reason, revoke_time tuple
      def revoked_cert(serial)
        @revoked_certs[serial]
      end

      # Adds a certificate to the revocation list. After calling you must call generate_crl to sign a new CRL
      #
      # @param serial [Integer] serial number of the certificate to revoke
      # @param reason [Integer,nil] reason for revocation
      # @param revoke_time [Integer]
      # @param write [Boolean] whether or not to write the revocation event. Should only be false if you're doing an initial load
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
      def revoke_cert(serial,reason=nil, revoke_time=Time.now.to_i, write=true)
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
        if write == true
          @rw.write_list_entry(serial, revoke_time, reason)
        end
        nil
      end

      # Remove serial from revocation list. After unrevoking you must call generate_crl to sign a new CRL
      #
      # @param serial [Integer] serial number of the certificate to remove from revocation
      def unrevoke_cert(serial)
        @revoked_certs.delete(serial)
        @rw.remove_list_entry(serial)
        nil
      end

      # Generate the CRL
      # @param last_update [Time] the lastUpdate for the CRL
      # @param next_update [Time] the nextUpdate for the CRL
      #
      # @return [R509::CRL::SignedList] signed CRL
      def generate_crl(last_update=Time.at(Time.now.to_i)-@config.crl_start_skew_seconds,next_update=Time.at(Time.now)+@config.crl_validity_hours*3600)
        # Time.at(Time.now.to_i) removes sub-second precision. Subsecond precision is irrelevant
        # for CRL update times and makes testing harder.
        crl = create_crl_object(last_update,next_update)

        self.revoked_certs.each do |serial, reason, revoke_time|
          revoked = OpenSSL::X509::Revoked.new
          revoked.serial = OpenSSL::BN.new serial.to_s
          revoked.time = Time.at(revoke_time)
          if not reason.nil?
            enum = OpenSSL::ASN1::Enumerated(reason)
            ext = OpenSSL::X509::Extension.new("CRLReason", enum)
            revoked.add_extension(ext)
          end
          # now add it to the crl
          crl.add_revoked(revoked)
        end

        crl.sign(@config.crl_cert.key.key, @crl_md.digest)
        R509::CRL::SignedList.new(crl)
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

      private

      def create_crl_object(last_update,next_update)
        crl = OpenSSL::X509::CRL.new
        crl.version = 1
        crl.last_update = last_update
        crl.next_update = next_update
        crl.issuer = @config.crl_cert.subject.name
        ef = OpenSSL::X509::ExtensionFactory.new
        ef.issuer_certificate = @config.crl_cert.cert
        ef.crl = crl
        crl_number = increment_crl_number
        crlnum = OpenSSL::ASN1::Integer(crl_number)
        crl.add_extension(OpenSSL::X509::Extension.new("crlNumber", crlnum))
        extensions = []
        extensions << ["authorityKeyIdentifier", "keyid", false]
        extensions.each do |oid, value, critical|
          crl.add_extension(ef.create_extension(oid, value, critical))
        end
        crl
      end

      # Increments the crl_number.
      # @return [Integer] the new CRL number
      #
      def increment_crl_number
        @crl_number += 1
        @rw.write_number(@crl_number)
        @crl_number
      end

    end
  end
end

