require "openssl"

module R509
    class Subject
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

        def name
            OpenSSL::X509::Name.new(@array)
        end

        def empty?
            @array.empty?
        end

        def [](key)
            @array.each do |item|
                if key == item[0]
                    return item[1]
                end
            end
            return nil
        end

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

        def delete(key)
            @array = @array.select do |item|
                item[0] != key
            end
        end

        def to_s
            name.to_s
        end

        def to_a
            @array
        end
    end
end
