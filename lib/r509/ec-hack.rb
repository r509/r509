# this hack exists to work around a major issue with the OpenSSL::PKey::EC interface
# as it is currently configured in ruby <= 2.0.0rc1
# the signing methods on OpenSSL::X509::Request and OpenSSL::X509::Certificate look for
# a method named #private? on the PKey object. OpenSSL::PKey::RSA and OpenSSL::PKey::DSA
# both define this method, but OpenSSL::PKey::EC defines #private_key? instead. This
# will open up the class and add #private? as an alias to allow successful signing
if defined?(OpenSSL::PKey::EC) and not OpenSSL::PKey::EC.method_defined?('private?')
  # marked as @private so it won't appear in the yard doc
  # @private
  module OpenSSL::PKey
    # marked as @private so it won't appear in the yard doc
    # @private
    class EC
      def private?
        private_key?
      end
    end
  end
end
