require 'openssl'

module R509
    #MessageDigest allows you to specify MDs in a more friendly fashion
    class MessageDigest
        attr_reader :name, :digest

        # @param [String,OpenSSL::Digest]
        def initialize(arg)
            if arg.kind_of?(String)
                @name = arg.downcase
                @digest = translate_name_to_digest
            else
                @digest = arg
                @name = translate_digest_to_name
            end
        end

        private

        # @return [OpenSSL::Digest]
        def translate_name_to_digest
            case @name
            when 'sha1' then OpenSSL::Digest::SHA1.new
            when 'sha256' then OpenSSL::Digest::SHA256.new
            when 'sha512' then OpenSSL::Digest::SHA512.new
            when 'md5' then OpenSSL::Digest::MD5.new
            when 'dss1' then OpenSSL::Digest::DSS1.new
            else
                @name = "sha1"
                OpenSSL::Digest::SHA1.new
            end
        end

        # @return [String]
        def translate_digest_to_name
            case @digest
            when OpenSSL::Digest::SHA1 then 'sha1'
            when OpenSSL::Digest::SHA256 then 'sha256'
            when OpenSSL::Digest::SHA512 then 'sha512'
            when OpenSSL::Digest::MD5 then 'md5'
            when OpenSSL::Digest::DSS1 then 'dss1'
            else
                raise ArgumentError, "Unknown digest"
            end
        end
    end
end

