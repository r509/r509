if !defined?(OpenSSL::PKey::EC)
  # this is a stub implementation for when EC is unavailable. Any method called against
  # it will raise an R509Error
  # marked as @private so it won't appear in the yard doc
  # @private
  module OpenSSL::PKey
    # marked as @private so it won't appear in the yard doc
    # @private
    class EC
      UNSUPPORTED = true
      def initialize(*args)
        raise R509::R509Error, "EC is unavailable. You may need to recompile Ruby with an OpenSSL that has elliptic curve support."
      end

      def method_missing(method, *args, &block)
        raise R509::R509Error, "EC is unavailable. You may need to recompile Ruby with an OpenSSL that has elliptic curve support."
      end
    end
  end
end
