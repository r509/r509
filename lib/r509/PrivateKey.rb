require 'openssl'
require 'r509/io_helpers'
require 'r509/Exceptions'

module R509
    #private key management
    class PrivateKey
        include R509::IOHelpers

        # @option opts [Symbol] :type :rsa/:dsa
        # @option opts [Integer] :bit_strength
        # @option opts [String] :password
        # @option opts [String,OpenSSL::PKey::RSA,OpenSSL::PKey::DSA] :key
        # @option opts [OpenSSL::Engine] :engine
        # @option opts [string] :key_name (used with engine)
        def initialize(opts)
            if not opts.kind_of?(Hash)
                raise ArgumentError, 'Must provide a hash of options'
            end

            if opts.has_key?(:engine) and opts.has_key?(:key)
                raise ArgumentError, 'You can\'t pass both :key and :engine'
            elsif opts.has_key?(:key_name) and not opts.has_key?(:engine)
                raise ArgumentError, 'When providing a :key_name you MUST provide an :engine'
            elsif opts.has_key?(:engine) and not opts.has_key?(:key_name)
                raise ArgumentError, 'When providing an :engine you MUST provide a :key_name'
            elsif opts.has_key?(:engine) and opts.has_key?(:key_name)
                if not opts[:engine].kind_of?(OpenSSL::Engine)
                    raise ArgumentError, 'When providing an engine, it must be of type OpenSSL::Engine'
                end
                @engine = opts[:engine]
                @key_name = opts[:key_name]
            end

            if opts.has_key?(:key)
                password = opts[:password] || nil
                #OpenSSL::PKey.read solves this begin/rescue garbage but is only
                #available to Ruby 1.9.3+
                begin
                    @key = OpenSSL::PKey::RSA.new(opts[:key],password)
                rescue OpenSSL::PKey::RSAError
                    begin
                        @key = OpenSSL::PKey::DSA.new(opts[:key],password)
                    rescue
                        raise R509::R509Error, "Failed to load private key. Invalid key or incorrect password."
                    end
                end
            else
                bit_strength = opts[:bit_strength] || 2048
                type = opts[:type] || :rsa
                case type
                when :rsa
                    @key = OpenSSL::PKey::RSA.new(bit_strength)
                when :dsa
                    @key = OpenSSL::PKey::DSA.new(bit_strength)
                else
                    raise ArgumentError, 'Must provide :rsa or :dsa as type when key or engine is nil'
                end
            end
        end

        # @return [Integer]
        def bit_strength
            if self.rsa?
                return self.public_key.n.to_i.to_s(2).size
            elsif self.dsa?
                return self.public_key.p.to_i.to_s(2).size
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

        # @return [OpenSSL::PKey::RSA,OpenSSL::PKey::DSA] public key
        def public_key
            self.key.public_key
        end

        alias :to_s :public_key

        # Converts the key into the PEM format
        #
        # @return [String] the CSR converted into PEM format.
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
        # @return [String] the CSR converted into encrypted PEM format.
        def to_encrypted_pem(cipher,password)
            if in_hardware?
                raise R509::R509Error, "This method cannot be called when using keys in hardware"
            end
            cipher = OpenSSL::Cipher::Cipher.new(cipher)
            self.key.to_pem(cipher,password)
        end


        # Converts the key into the DER format
        #
        # @return [String] the CSR converted into DER format.
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
            write_data(filename_or_io, self.key.to_pem)
        end


        # Writes the key into encrypted PEM format with specified cipher
        #
        # @param [String, #write] filename_or_io Either a string of the path for
        #  the file that you'd like to write, or an IO-like object.
        # @param [String,OpenSSL::Cipher] cipher to use for encryption
        # full list of available ciphers can be obtained with OpenSSL::Cipher.ciphers
        # (common ones are des3, aes256, aes128)
        # @param [String] password password
        def write_encrypted_pem(filename_or_io,cipher,password)
            write_data(filename_or_io, to_encrypted_pem(cipher,password))
        end

        # Writes the key into the DER format
        #
        # @param [String, #write] filename_or_io Either a string of the path for
        #  the file that you'd like to write, or an IO-like object.
        def write_der(filename_or_io)
            write_data(filename_or_io, self.key.to_der)
        end


        # Returns whether the public key is RSA
        #
        # @return [Boolean] true if the public key is RSA, false otherwise
        def rsa?
            self.key.kind_of?(OpenSSL::PKey::RSA)
        end

        # Returns whether the public key is DSA
        #
        # @return [Boolean] true if the public key is DSA, false otherwise
        def dsa?
            self.key.kind_of?(OpenSSL::PKey::DSA)
        end
    end
end
