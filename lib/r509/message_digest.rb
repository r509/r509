require 'openssl'

module R509
  # MessageDigest allows you to specify MDs in a more friendly fashion
  class MessageDigest
    # a list of message digests that this class understands
    KNOWN_MDS = ['SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512', 'DSS1', 'MD5']

    # this constant defines the default message digest if it is not supplied
    # or an invalid digest is passed
    DEFAULT_MD = 'SHA256'

    attr_reader :name, :digest

    # @param [String,OpenSSL::Digest] arg
    def initialize(arg = nil)
      if arg.is_a?(String)
        @name = arg.downcase
        @digest = translate_name_to_digest
      elsif arg.nil?
        @name = DEFAULT_MD
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
      when 'sha224' then OpenSSL::Digest::SHA224.new
      when 'sha256' then OpenSSL::Digest::SHA256.new
      when 'sha384' then OpenSSL::Digest::SHA384.new
      when 'sha512' then OpenSSL::Digest::SHA512.new
      when 'md5' then OpenSSL::Digest::MD5.new
      when 'dss1' then OpenSSL::Digest::DSS1.new
      else
        @name = DEFAULT_MD.downcase
        translate_name_to_digest
      end
    end

    # @return [String]
    def translate_digest_to_name
      case @digest
      when OpenSSL::Digest::SHA1 then 'sha1'
      when OpenSSL::Digest::SHA224 then 'sha224'
      when OpenSSL::Digest::SHA256 then 'sha256'
      when OpenSSL::Digest::SHA384 then 'sha384'
      when OpenSSL::Digest::SHA512 then 'sha512'
      when OpenSSL::Digest::MD5 then 'md5'
      when OpenSSL::Digest::DSS1 then 'dss1'
      else
        raise ArgumentError, "Unknown digest"
      end
    end
  end
end
