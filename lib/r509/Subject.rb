require "openssl"

module R509
    #subject class. Used for building OpenSSL::X509::Name objects in a sane fashion
    class Subject
        # @param [Array, OpenSSL::X509::Name, R509::Subject]
        def initialize(arg=nil)
            case arg
            when Array
                @array = arg
            when OpenSSL::X509::Name
                @array = arg.to_a
            when R509::Subject
                @array = arg.to_a
            else
                @array = []
            end

            # see if X509 thinks this is okay
            name
        end

        # @return [OpenSSL::X509::Name]
        def name
            OpenSSL::X509::Name.new(@array)
        end

        # @return [Boolean]
        def empty?
            @array.empty?
        end

        # get value for key
        def [](key)
            @array.each do |item|
                if key == item[0]
                    return item[1]
                end
            end
            return nil
        end

        # set key and value
        def []=(key, value)
            added = false
            @array = @array.map{ |item|
                if key == item[0]
                    added = true
                    [key, value]
                else
                    item
                end
            }

            if not added
                @array << [key, value]
            end

            # see if X509 thinks this is okay
            name

            @array
        end

        # @param [String] key item you want deleted
        def delete(key)
            @array = @array.select do |item|
                item[0] != key
            end
        end

        # @return [String] string of form /CN=something.com/O=whatever/L=Locality
        def to_s
            name.to_s
        end

        # @return [Array] Array of form [['CN','langui.sh'],['O','Org']]
        def to_a
            @array
        end
    end
end
