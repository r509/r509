require 'openssl'

module R509
    class MessageDigest
        attr_reader :name, :digest

        def initialize(*args)
            case args.size
            when 1
                arg = args[0]

                if arg.kind_of?(String)
                    @name = arg.downcase
                    @digest = translate_name_to_digest
                else
                    @digest = arg
                    @name = translate_digest_to_name
                end
            else
                raise ArgumentError, "Expected 1 argument, got #{args.size}"
            end
            @name = name
        end

        private

        def translate_name_to_digest
            case @name
            when 'sha1' then OpenSSL::Digest::SHA1.new
            when 'sha256' then OpenSSL::Digest::SHA256.new
            when 'sha512' then OpenSSL::Digest::SHA512.new
            when 'md5' then OpenSSL::Digest::MD5.new
            else 
                @name = "sha1"
                OpenSSL::Digest::SHA1.new
            end
        end

        def translate_digest_to_name
            case @digest
            when OpenSSL::Digest::SHA1 then 'sha1'
            when OpenSSL::Digest::SHA256 then 'sha256'
            when OpenSSL::Digest::SHA512 then 'sha512'
            when OpenSSL::Digest::MD5 then 'md5'
            else
                raise ArgumentError, "Unknown digest"
            end
        end
    end
end

