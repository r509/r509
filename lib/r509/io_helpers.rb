module R509
    # helper methods for I/O
    module IOHelpers
        # Writes data into an IO or file
        # @param [String, #write] filename_or_io Either a string of the path for
        #  the file that you'd like to write, or an IO-like object.
        # @param [String] data The data that we want to write
        def self.write_data(filename_or_io, data)
            if filename_or_io.respond_to?(:write)
                filename_or_io.write(data)
            else
                begin
                    file = File.open(filename_or_io, 'wb:ascii-8bit')
                    return file.write(data)
                ensure
                    file.close()
                end
            end
        end

        # Reads data from an IO or file
        # @param [String, #write] filename_or_io Either a string of the path for
        #  the file that you'd like to read, or an IO-like object.
        # @param [String] data The data that we want to write
        def self.read_data(filename_or_io)
            if filename_or_io.respond_to?(:read)
                filename_or_io.read()
            else
                begin
                    file = File.open(filename_or_io, 'rb:ascii-8bit')
                    return file.read()
                ensure
                    file.close()
                end
            end
        end
        
        def write_data(filename_or_io, data)
          IOHelpers.write_data(filename_or_io, data)
        end
        
        def read_data(filename_or_io)
          IOHelpers.read_data(filename_or_io)
        end
    end
end
