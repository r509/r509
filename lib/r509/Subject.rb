require "openssl"

module R509
    class Subject
        attr_reader :name

        def initialize(arg=nil)
            case arg
            when Array
                @name = OpenSSL::X509::Name.new(arg)
            when OpenSSL::X509::Name
                @name = arg
            when R509::Subject
                @name = arg.name
            else
                @name = OpenSSL::X509::Name.new
            end
        end

        def []=(key, value)
            added = false
            @name = OpenSSL::X509::Name.new(@name.to_a.map{ |item|
                if key == item[0]
                    added = true
                    [key, value]
                else
                    item
                end
            })

            if not added
                @name.add_entry(key, value)
            end
        end

        def delete(key)
            @name = OpenSSL::X509::Name.new(@name.to_a.select{ |item| item[0] != key })
        end

        def to_s
            @name.to_s
        end
    end
end
