module R509
    module IOHelpers
        # Writes data into an IO or file
        # @param [String, #write] filename_or_io Either a string of the path for
        #  the file that you'd like to write, or an IO-like object.
        # @param [String] data The data that we want to write
        def write_data(filename_or_io, data)
            if filename_or_io.respond_to?(:write)
                filename_or_io.write(data)
            else
                File.open(filename_or_io, 'wb:ascii-8bit') {|f| f.write(data) }
            end
        end

        # Reads data from an IO or file
        # @param [String, #write] filename_or_io Either a string of the path for
        #  the file that you'd like to read, or an IO-like object.
        # @param [String] data The data that we want to write
        def read_data(filename_or_io)
            if filename_or_io.respond_to?(:read)
                filename_or_io.read()
            else
                File.open(filename_or_io, 'rb:ascii-8bit') {|f| f.read() }
            end
        end
    end
end
