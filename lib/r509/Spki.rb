require 'openssl'
require 'r509/Exceptions'
require 'r509/io_helpers'

module R509
    # The primary certificate signing request object
    class Spki
        include R509::IOHelpers

        attr_reader :subject, :spki, :san_names
        # @option opts [String,OpenSSL::Netscape::SPKI] :spki the spki you want to parse
        # @option opts [R509::Subject,Array,OpenSSL::X509::Name] :subject array of subject items
        # @example [['CN','langui.sh'],['ST','Illinois'],['L','Chicago'],['C','US'],['emailAddress','ca@langui.sh']]
        # you can also pass OIDs (see tests)
        # @option opts [Array] :san_names array of SAN names
        def initialize(opts={})
            if not opts.kind_of?(Hash)
                raise ArgumentError, 'Must provide a hash of options'
            end
            if opts.has_key?(:spki) and not opts.has_key?(:subject)
                raise ArgumentError, "Must provide both spki and subject"
            end
            if opts.has_key?(:san_names) and not opts[:san_names].kind_of?(Array)
                raise ArgumentError, "if san_names are provided they must be in an Array"
            end
            @spki = OpenSSL::Netscape::SPKI.new(opts[:spki].sub("SPKAC=",""))
            @subject = R509::Subject.new(opts[:subject])
            @san_names = opts[:san_names] || []
        end

        # @return [OpenSSL::PKey::RSA] public key
        def public_key
            @spki.public_key
        end

        # Converts the SPKI into the PEM format
        #
        # @return [String] the SPKI converted into PEM format.
        def to_pem
            @spki.to_pem
        end

        alias :to_s :to_pem

        # Converts the SPKI into the DER format
        #
        # @return [String] the SPKI converted into DER format.
        def to_der
            @spki.to_der
        end

        # Writes the SPKI into the PEM format
        #
        # @param [String, #write] filename_or_io Either a string of the path for
        #  the file that you'd like to write, or an IO-like object.
        def write_pem(filename_or_io)
            write_data(filename_or_io, @spki.to_pem)
        end

        # Writes the SPKI into the DER format
        #
        # @param [String, #write] filename_or_io Either a string of the path for
        #  the file that you'd like to write, or an IO-like object.
        def write_der(filename_or_io)
            write_data(filename_or_io, @spki.to_der)
        end

        # Returns whether the public key is RSA
        #
        # @return [Boolean] true if the public key is RSA, false otherwise
        def rsa?
            @spki.public_key.kind_of?(OpenSSL::PKey::RSA)
        end

        # Returns whether the public key is DSA
        #
        # @return [Boolean] true if the public key is DSA, false otherwise
        def dsa?
            @spki.public_key.kind_of?(OpenSSL::PKey::DSA)
        end

        # Returns the bit strength of the key used to create the SPKI
        # @return [Integer] the integer bit strength.
        def bit_strength
            if self.rsa?
                return @spki.public_key.n.to_i.to_s(2).size
            elsif self.dsa?
                return @spki.public_key.p.to_i.to_s(2).size
            end
        end

        # Returns key algorithm (RSA/DSA)
        # #
        # # @return [String] value of the key algorithm. RSA or DSA
        def key_algorithm
            if not @spki.nil?
                if @spki.public_key.kind_of? OpenSSL::PKey::RSA then
                    'RSA'
                elsif @spki.public_key.kind_of? OpenSSL::PKey::DSA then
                    'DSA'
                end
            else
                nil
            end
        end

        # Returns a hash structure you can pass to the Ca
        # You will want to call this method if you intend to alter the values
        # and then pass them to the Ca class.
        #
        # @return [Hash] :subject and :san_names you can pass to Ca
        def to_hash
            { :subject => @subject.dup , :san_names => @san_names.dup }
        end
    end
end
