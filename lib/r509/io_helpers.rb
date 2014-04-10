module R509
  # helper methods for I/O
  # @private
  module IOHelpers
    # Writes data into an IO or file
    # @param [String, #write] filename_or_io Either a string of the path for
    #  the file that you'd like to write, or an IO-like object.
    # @param [String] data The data that we want to write
    # @param [String] mode The write mode
    def self.write_data(filename_or_io, data, mode = 'wb:ascii-8bit')
      if filename_or_io.respond_to?(:write)
        if filename_or_io.kind_of?(StringIO) and mode != "a:ascii-8bit"
          # Writing to a StringIO in a non-append mode. This requires
          # us to rewind and truncate it first.
          filename_or_io.rewind
          filename_or_io.truncate(0)
        end
        filename_or_io.write(data)
      else
        return File.open(filename_or_io, mode) do |f|
          f.write(data)
        end
      end
    end

    # Reads data from an IO or file
    # @param [String, #read] filename_or_io Either a string of the path for
    #  the file that you'd like to read, or an IO-like object.
    def self.read_data(filename_or_io)
      if filename_or_io.respond_to?(:read)
        if filename_or_io.kind_of?(StringIO)
          filename_or_io.rewind
        end
        filename_or_io.read
      else
        return File.open(filename_or_io, 'rb:ascii-8bit') do |f|
          f.read
        end
      end
    end

    # Writes data into an IO or file
    # @param [String, #write] filename_or_io Either a string of the path for
    #  the file that you'd like to write, or an IO-like object.
    # @param [String] data The data that we want to write
    def write_data(filename_or_io, data, mode = 'wb:ascii-8bit')
      IOHelpers.write_data(filename_or_io, data, mode)
    end

    # Reads data from an IO or file
    # @param [String, #read] filename_or_io Either a string of the path for
    #  the file that you'd like to read, or an IO-like object.
    def read_data(filename_or_io)
      IOHelpers.read_data(filename_or_io)
    end
  end
end
