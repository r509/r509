require 'openssl'
require 'r509/io_helpers'
require 'r509/exceptions'

module R509
  # private key management
  class PrivateKey
    include R509::IOHelpers

    # a list of key types
    KNOWN_TYPES = ["RSA", "DSA", "EC"]
    # the default type
    DEFAULT_TYPE = "RSA"
    # default bit length for DSA/RSA
    DEFAULT_STRENGTH = 2048
    # default curve name for EC
    DEFAULT_CURVE = "secp384r1"

    # @option opts [Symbol] :type Defaults to R509::PrivateKey::DEFAULT_TYPE. Allows R509::PrivateKey::KNOWN_TYPES.
    # @option opts [String] :curve_name ("secp384r1") Only used if :type is EC
    # @option opts [Integer] :bit_length (2048) Only used if :type is RSA or DSA
    # @option opts [Integer] :bit_strength (2048) Deprecated, identical to bit_length.
    # @option opts [String] :password
    # @option opts [String,OpenSSL::PKey::RSA,OpenSSL::PKey::DSA,OpenSSL::PKey::EC] :key
    # @option opts [OpenSSL::Engine] :engine
    # @option opts [string] :key_name (used with engine)
    def initialize(opts = {})
      unless opts.kind_of?(Hash)
        raise ArgumentError, 'Must provide a hash of options'
      end
      validate_engine(opts)

      if opts.key?(:key)
        validate_key(opts)
      else
        generate_key(opts)
      end
    end

    # Helper method to quickly load a private key from the filesystem
    #
    # @param [String] filename Path to file you want to load
    # @return [R509::PrivateKey] PrivateKey object
    def self.load_from_file(filename, password = nil)
      R509::PrivateKey.new(:key => IOHelpers.read_data(filename), :password => password)
    end

    # Returns the bit length of the key
    #
    # @return [Integer]
    def bit_length
      if self.rsa?
        return self.public_key.n.num_bits
      elsif self.dsa?
        return self.public_key.p.num_bits
      elsif self.ec?
        raise R509::R509Error, 'Bit length is not available for EC at this time.'
      end
    end
    alias_method :bit_strength, :bit_length

    # Returns the short name of the elliptic curve used to generate the private key
    # if the key is EC. If not, raises an error.
    #
    # @return [String] elliptic curve name
    def curve_name
      if self.ec?
        self.key.group.curve_name
      else
        raise R509::R509Error, 'Curve name is only available with EC private keys'
      end
    end

    # @return [OpenSSL::PKey::RSA,OpenSSL::PKey::DSA,OpenSSL::Engine pkey] this method may return the PKey object itself or a handle to the private key in the HSM (which will not show the private key, just public)
    def key
      if in_hardware?
        @engine.load_private_key(@key_name)
      else
        @key
      end
    end

    # @return [Boolean] whether the key is resident in hardware or not
    def in_hardware?
      if not @engine.nil?
        true
      else
        false
      end
    end

    # @return [OpenSSL::PKey::RSA,OpenSSL::PKey::DSA,OpenSSL::PKey::EC] public key
    def public_key
      if self.ec?
        # OpenSSL::PKey::EC.public_key returns an OpenSSL::PKey::EC::Point, which isn't consistent
        # with the way OpenSSL::PKey::RSA/DSA do it. We could return the original PKey::EC object
        # but if we do that then it has the private_key as well. Here's a ghetto workaround.
        # We have to supply the curve name to the temporary key object or else #public_key= fails
        curve_name = self.key.group.curve_name
        temp_key = OpenSSL::PKey::EC.new(curve_name)
        temp_key.public_key = self.key.public_key
        temp_key
      else
        self.key.public_key
      end
    end

    alias_method :to_s, :public_key

    # Converts the key into the PEM format
    #
    # @return [String] the key converted into PEM format.
    def to_pem
      if in_hardware?
        raise R509::R509Error, "This method cannot be called when using keys in hardware"
      end
      self.key.to_pem
    end

    # Converts the key into encrypted PEM format
    #
    # @param [String,OpenSSL::Cipher] cipher to use for encryption
    # full list of available ciphers can be obtained with OpenSSL::Cipher.ciphers
    # (common ones are des3, aes256, aes128)
    # @param [String] password password
    # @return [String] the key converted into encrypted PEM format.
    def to_encrypted_pem(cipher, password)
      if in_hardware?
        raise R509::R509Error, "This method cannot be called when using keys in hardware"
      end
      cipher = OpenSSL::Cipher::Cipher.new(cipher)
      self.key.to_pem(cipher, password)
    end

    # Converts the key into the DER format
    #
    # @return [String] the key converted into DER format.
    def to_der
      if in_hardware?
        raise R509::R509Error, "This method cannot be called when using keys in hardware"
      end
      self.key.to_der
    end

    # Writes the key into the PEM format
    #
    # @param [String, #write] filename_or_io Either a string of the path for
    #  the file that you'd like to write, or an IO-like object.
    def write_pem(filename_or_io)
      write_data(filename_or_io, self.to_pem)
    end

    # Writes the key into encrypted PEM format with specified cipher
    #
    # @param [String, #write] filename_or_io Either a string of the path for
    #  the file that you'd like to write, or an IO-like object.
    # @param [String,OpenSSL::Cipher] cipher to use for encryption
    # full list of available ciphers can be obtained with OpenSSL::Cipher.ciphers
    # (common ones are des3, aes256, aes128)
    # @param [String] password password
    def write_encrypted_pem(filename_or_io, cipher, password)
      write_data(filename_or_io, to_encrypted_pem(cipher, password))
    end

    # Writes the key into the DER format
    #
    # @param [String, #write] filename_or_io Either a string of the path for
    #  the file that you'd like to write, or an IO-like object.
    def write_der(filename_or_io)
      write_data(filename_or_io, self.to_der)
    end

    # Returns whether the key is RSA
    #
    # @return [Boolean] true if the key is RSA, false otherwise
    def rsa?
      self.key.kind_of?(OpenSSL::PKey::RSA)
    end

    # Returns whether the key is DSA
    #
    # @return [Boolean] true if the key is DSA, false otherwise
    def dsa?
      self.key.kind_of?(OpenSSL::PKey::DSA)
    end

    # Returns whether the key is EC
    #
    # @return [Boolean] true if the key is EC, false otherwise
    def ec?
      self.key.kind_of?(OpenSSL::PKey::EC)
    end

    private

    def validate_engine(opts)
      if opts.key?(:engine) and opts.key?(:key)
        raise ArgumentError, 'You can\'t pass both :key and :engine'
      elsif opts.key?(:key_name) and not opts.key?(:engine)
        raise ArgumentError, 'When providing a :key_name you MUST provide an :engine'
      elsif opts.key?(:engine) and not opts.key?(:key_name)
        raise ArgumentError, 'When providing an :engine you MUST provide a :key_name'
      elsif opts.key?(:engine) and opts.key?(:key_name)
        unless opts[:engine].kind_of?(OpenSSL::Engine)
          raise ArgumentError, 'When providing an engine, it must be of type OpenSSL::Engine'
        end
        @engine = opts[:engine]
        @key_name = opts[:key_name]
      end
    end

    def validate_key(opts)
      password = opts[:password] || nil
      # OpenSSL::PKey.read solves this begin/rescue garbage but is only
      # available to Ruby 1.9.3+ and may not solve the EC portion
      begin
        @key = OpenSSL::PKey::RSA.new(opts[:key], password)
      rescue OpenSSL::PKey::RSAError
        begin
          @key = OpenSSL::PKey::DSA.new(opts[:key], password)
        rescue
          begin
            @key = OpenSSL::PKey::EC.new(opts[:key], password)
          rescue
            raise R509::R509Error, "Failed to load private key. Invalid key or incorrect password."
          end
        end
      end
    end

    def generate_key(opts)
      bit_length = opts[:bit_length] || opts[:bit_strength] || DEFAULT_STRENGTH
      type = opts[:type] || DEFAULT_TYPE
      case type.upcase
      when "RSA"
        @key = OpenSSL::PKey::RSA.new(bit_length)
      when "DSA"
        @key = OpenSSL::PKey::DSA.new(bit_length)
      when "EC"
        curve_name = opts[:curve_name] || DEFAULT_CURVE
        @key = OpenSSL::PKey::EC.new(curve_name)
        @key.generate_key
      else
        raise ArgumentError, "Must provide #{KNOWN_TYPES.join(", ")} as type when key or engine is nil"
      end
    end
  end
end
