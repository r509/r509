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
            @name.add_entry(key, value)
        end

        def to_s
            @name.to_s
        end
    end
end
