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
      def self.load_from_file(filename)
        return R509::CRL::SignedList.new(IOHelpers.read_data(filename))
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

      alias_method :to_s, :to_pem

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
  end
end
