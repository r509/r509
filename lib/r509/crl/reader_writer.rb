require 'openssl'
require 'r509/config'
require 'r509/exceptions'
require 'r509/io_helpers'

module R509
  # contains CRL related classes (generator and a pre-existing list loader)
  module CRL
    # Abstract base class for a CRL writer. Use this to construct a subclass that can then be passed to
    # R509::CRL::Administrator to read/write CRL data with whatever backend you want.
    class ReaderWriter
      def write_list_entry
        raise NotImplementedError, "You must call #write_list_entry on a subclass of ReaderWriter"
      end

      def remove_list_entry
        raise NotImplementedError, "You must call #remove_list_entry on a subclass of ReaderWriter"
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

    # File-based implementation of the CRL reader/writer. Uses the crl_number_file and crl_list_file attributes in CAConfig
    class FileReaderWriter < R509::CRL::ReaderWriter
      include R509::IOHelpers

      attr_accessor :crl_number_file, :crl_list_file

      def initialize
        @crl_number_file = nil
        @crl_list_file = nil
      end

      # Reads a CRL list file from a file or StringIO
      # @yield For each revoked certificate in the CRL
      # @yieldparam serial [Integer] revoked certificate's serial number
      # @yieldparam reason [Integer,nil] reason for revocation.
      # @yieldparam revoke_time [Integer]
      def read_list
        return nil if @crl_list_file.nil?

        data = read_data(@crl_list_file)

        data.each_line do |line|
          line.chomp!
          serial,  revoke_time, reason = line.split(',', 3)
          serial = serial.to_i
          reason = (reason == '') ? nil : reason.to_i
          revoke_time = (revoke_time == '') ? nil : revoke_time.to_i
          yield serial, reason, revoke_time
        end
        nil
      end

      # Appends a CRL list entry to a file or StringIO
      # @param serial [Integer] serial number of the certificate to revoke
      # @param reason [Integer,nil] reason for revocation
      # @param revoke_time [Integer]
      def write_list_entry(serial, revoke_time, reason)
        return nil if @crl_list_file.nil?

        entry = [serial,revoke_time,reason].join(",")
        write_data(@crl_list_file, entry + "\n" ,'a:ascii-8bit')
      end

      # Remove a CRL list entry
      # @param serial [Integer] serial number of the certificate to remove from the list
      def remove_list_entry(serial)
        return nil if @crl_list_file.nil?

        data = read_data(@crl_list_file)

        updated_list = []

        data.each_line do |line|
          line.chomp!
          revoke_info = line.split(',', 3)
          if revoke_info[0].to_i != serial
            updated_list.push(line)
          end
        end
        write_data(@crl_list_file, updated_list.join("\n") + "\n")
        nil
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
