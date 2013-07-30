require 'openssl'
require 'r509/config'
require 'r509/exceptions'
require 'r509/io_helpers'

module R509
  # contains CRL related classes (generator and a pre-existing list loader)
  module CRL
    # Abstract base class for a CRL writer
    class ReaderWriter
      def write_list_entry
        raise NotImplementedError, "You must call #write_list_entry on a subclass of ReaderWriter"
      end

      def write_number
        raise NotImplementedError, "You must call #write_number on a subclass of ReaderWriter"
      end

      def read_list
        raise NotImplementedError, "You must call #read_list on a subclass of ReaderWriter"
      end

      def read_number
        raise NotImplementedError, "You must call #read_number on a subclass of ReaderWriter"
      end
    end

    # File-based implementation of the CRL reader/writer
    class FileReaderWriter < R509::CRL::ReaderWriter
      include R509::IOHelpers

      attr_accessor :crl_number_file, :crl_list_file

      def initialize
        @crl_number_file = nil
        @crl_list_file = nil
      end

      # Reads a CRL list file from a file or StringIO
      # @param admin [R509::CRL::Administrator] the parent CRL Administrator object
      def read_list(admin)
        return nil if @crl_list_file.nil?

        data = read_data(@crl_list_file)

        data.each_line do |line|
          line.chomp!
          serial,  revoke_time, reason = line.split(',', 3)
          serial = serial.to_i
          reason = (reason == '') ? nil : reason.to_i
          revoke_time = (revoke_time == '') ? nil : revoke_time.to_i
          admin.revoke_cert(serial, reason, revoke_time, false)
        end
        nil
      end

      # Appends a CRL list entry to a file or StringIO
      # @param serial [Integer] serial number of the certificate to revoke
      # @param reason [Integer,nil] reason for revocation
      # @param revoke_time [Integer]
      def write_list_entry(serial,time,reason)
        return nil if @crl_list_file.nil?

        entry = [serial,time,reason].join(",")
        write_data(@crl_list_file, entry+"\n" ,'wa:ascii-8bit')
      end

      # read the CRL number from a file or StringIO
      def read_number
        return 0 if @crl_number_file.nil?

        read_data(@crl_number_file).to_i
      end

      # write the CRL number to a file or StringIO
      def write_number(crl_number)
        return nil if @crl_number_file.nil?

        write_data(@crl_number_file,crl_number.to_s)
      end
    end
  end
end

