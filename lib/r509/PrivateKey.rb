require 'openssl'
require 'r509/io_helpers'
require 'r509/Exceptions'

module R509
    #private key management
    class PrivateKey
        include R509::IOHelpers

        attr_reader :bit_strength, :key

        # @option opts [Symbol] :type :rsa/:dsa
        # @option opts [Integer] :bit_strength
        # @option opts [String] :password
        # @option opts [String,OpenSSL::PKey::RSA,OpenSSL::PKey::DSA] :key
        def initialize(opts)
            if not opts.kind_of?(Hash)
                raise ArgumentError, 'Must provide a hash of options'
            end
            type = opts[:type] || :rsa
            if type != :rsa and type != :dsa and @key.nil?
                raise ArgumentError, 'Must provide :rsa or :dsa as type when key is nil'
            end
            @bit_strength = opts[:bit_strength] || 2048
            password = opts[:password] || nil

            if opts.has_key?(:key)
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
                case type
                when :rsa
                    @key = OpenSSL::PKey::RSA.new(@bit_strength)
                when :dsa
                    @key = OpenSSL::PKey::DSA.new(@bit_strength)
                end
            end
        end

        # @return [OpenSSL::PKey::RSA,OpenSSL::PKey::RSA] public key
        def public_key
            @key.public_key
        end

        # Converts the key into the PEM format
        #
        # @return [String] the CSR converted into PEM format.
        def to_pem
            @key.to_pem
        end

        alias :to_s :to_pem

        # Converts the key into encrypted PEM format
        #
        # @param [String,OpenSSL::Cipher] cipher to use for encryption
        # full list of available ciphers can be obtained with OpenSSL::Cipher.ciphers
        # (common ones are des3, aes256, aes128)
        # @param [String] password password
        # @return [String] the CSR converted into encrypted PEM format.
        def to_encrypted_pem(cipher,password)
            cipher = OpenSSL::Cipher::Cipher.new(cipher)
            @key.to_pem(cipher,password)
        end


        # Converts the key into the DER format
        #
        # @return [String] the CSR converted into DER format.
        def to_der
            @key.to_der
        end

        # Writes the key into the PEM format
        #
        # @param [String, #write] filename_or_io Either a string of the path for
        #  the file that you'd like to write, or an IO-like object.
        def write_pem(filename_or_io)
            write_data(filename_or_io, @key.to_pem)
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
            write_data(filename_or_io, @key.to_der)
        end


        # Returns whether the public key is RSA
        #
        # @return [Boolean] true if the public key is RSA, false otherwise
        def rsa?
            @key.kind_of?(OpenSSL::PKey::RSA)
        end

        # Returns whether the public key is DSA
        #
        # @return [Boolean] true if the public key is DSA, false otherwise
        def dsa?
            @key.kind_of?(OpenSSL::PKey::DSA)
        end
    end
end
