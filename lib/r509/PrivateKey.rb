require 'openssl'
require 'r509/io_helpers'
require 'r509/Exceptions'

module R509
    class PrivateKey
        include R509::IOHelpers

        attr_reader :type, :bit_strength, :key

        # @ options [] opts
        # @options opts [Symbol] :type :rsa/:dsa
        # @options opts [Integer] :bit_strength
        # @options opts [String] :password
        # @options opts [String,OpenSSL::PKey::RSA,OpenSSL::PKey::DSA] :key
        def initialize(opts)
            if not opts.kind_of?(Hash)
                raise ArgumentError, 'Must provide a hash of options'
            end
            @type = opts[:type] || :rsa
            if @type != :rsa and @type != :dsa
                raise ArgumentError, 'Must provide :rsa or :dsa as type'
            end
            @bit_strength = opts[:bit_strength] || 2048
            password = opts[:password] || nil

            if opts.has_key?(:key)
                begin
                    case @type
                    when :rsa
                        #TODO: Replace with OpenSSL::PKey.read ?
                        @key = OpenSSL::PKey::RSA.new(opts[:key],password)
                    when :dsa
                        @key = OpenSSL::PKey::DSA.new(opts[:key],password)
                    end
                rescue
                    raise R509::R509Error, "Failed to load private key. Invalid key or incorrect password."
                end
            else
                case @type
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
    end
end
