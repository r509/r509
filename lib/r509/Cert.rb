require 'openssl'
require 'r509/Exceptions'
require 'r509/io_helpers'

module R509
    # The primary certificate object.
    class Cert
    include R509::IOHelpers

        attr_reader :cert, :key

        # @option opts [String,OpenSSL::X509::Certificate] :cert a cert
        # @option opts [R509::PrivateKey,String] :key optional private key to supply. either an unencrypted PEM/DER string or an R509::PrivateKey object (use the latter if you need password/hardware support)
        # @option opts [String] :pkcs12 a PKCS12 object containing both key and cert
        # @option opts [String] :password password for PKCS12 or private key (if supplied)
        def initialize(opts={})
            if not opts.kind_of?(Hash)
                raise ArgumentError, 'Must provide a hash of options'
            end
            if opts.has_key?(:pkcs12) and ( opts.has_key?(:key) or opts.has_key?(:cert) )
                raise ArgumentError, "When providing pkcs12, do not pass cert or key"
            elsif opts.has_key?(:pkcs12)
                pkcs12 = OpenSSL::PKCS12.new( opts[:pkcs12], opts[:password] )
                parse_certificate(pkcs12.certificate)
                @key = R509::PrivateKey.new( :key => pkcs12.key )
            elsif not opts.has_key?(:cert)
                raise ArgumentError, 'Must provide :cert or :pkcs12'
            else
                parse_certificate(opts[:cert])
            end

            if opts.has_key?(:key)
                if opts[:key].kind_of?(R509::PrivateKey)
                    @key = opts[:key]
                else
                    @key = R509::PrivateKey.new( :key => opts[:key], :password => opts[:password] )
                end
            end
            if not @key.nil?
                if not @cert.public_key.to_s == @key.public_key.to_s then
                    raise R509Error, 'Key does not match cert.'
                end
            end
        end

        # Converts the Cert into the PEM format
        #
        # @return [String] the Cert converted into PEM format.
        def to_pem
            if @cert.kind_of?(OpenSSL::X509::Certificate)
                return @cert.to_pem.chomp
            end
        end

        alias :to_s :to_pem

        # Converts the Cert into the DER format
        #
        # @return [String] the Cert converted into DER format.
        def to_der
            if @cert.kind_of?(OpenSSL::X509::Certificate)
                return @cert.to_der
            end
        end

        # Returns beginning (notBefore) of certificate validity period
        #
        # @return [Time] time object
        def not_before
            @cert.not_before
        end

        # Returns the serial number of the certificate in decimal form
        #
        # @return [Integer]
        def serial
            @cert.serial.to_i
        end

        # Returns ending (notAfter) of certificate validity period
        #
        # @return [Time] time object
        def not_after
            @cert.not_after
        end

        # Returns the certificate public key
        #
        # @return [OpenSSL::PKey::RSA] public key object
        def public_key
            @cert.public_key
        end

        # Returns the issuer
        #
        # @return [OpenSSL::X509::Name] issuer object. Can be parsed as string easily
        def issuer
            @cert.issuer
        end

        # Returns the certificate fingerprint with the specified algorithm (default sha1)
        #
        # @return [String] hex digest of the certificate
        def fingerprint(algorithm='sha1')
            message_digest = R509::MessageDigest.new(algorithm)
            md = message_digest.digest
            md.update(@cert.to_der)
            md.to_s
        end

        # Returns the subject
        #
        # @return [OpenSSL::X509::Name] subject object. Can be parsed as string easily
        def subject
            @cert.subject
        end

        # @return [Boolean] Boolean of whether the object contains a private key
        def has_private_key?
            if not @key.nil?
                true
            else
                false
            end
        end

        # @return [Array] list of SAN names
        def san_names
            @san_names || []
        end


        # Returns subject component
        #
        # @return [String] value of the subject component requested
        def subject_component short_name
            match = @cert.subject.to_a.find { |x| x[0] == short_name }
            return nil if match.nil?
            return match[1]
        end

        # Return the CN, as well as all the subject alternative names (SANs).
        #
        # @return [Array] the array of names. Returns an empty array if 
        #  there are no names, at all.
        def subject_names
            ret = []
            if cn = self.subject_component('CN')
                ret << cn
            end
            # Merge in san_names if we got anything.
            if sn = self.san_names
                ret.concat(sn)
            end

            return ret.sort.uniq
        end

        # Returns whether the public key is RSA
        #
        # @return [Boolean] true if the public key is RSA, false otherwise
        def rsa?
            @cert.public_key.kind_of?(OpenSSL::PKey::RSA)
        end

        # Returns whether the public key is DSA
        #
        # @return [Boolean] true if the public key is DSA, false otherwise
        def dsa?
            @cert.public_key.kind_of?(OpenSSL::PKey::DSA)
        end

        # Returns the bit strength of the key used to create the certificate
        #
        # @return [Integer] integer value of bit strength
        def bit_strength
            if self.rsa?
                return @cert.public_key.n.num_bits
            elsif self.dsa?
                return @cert.public_key.p.num_bits
            end
        end

        # Returns signature algorithm
        #
        # @return [String] value of the signature algorithm. E.g. sha1WithRSAEncryption, sha256WithRSAEncryption, md5WithRSAEncryption
        def signature_algorithm
            @cert.signature_algorithm
        end

        # Returns key algorithm (RSA or DSA)
        #
        # @return [String] value of the key algorithm. RSA or DSA
        def key_algorithm
            if self.rsa?
                "RSA"
            elsif self.dsa?
                "DSA"
            end
        end

        # Writes the Cert into the PEM format
        # @param [String, #write] filename_or_io Either a string of the path for
        #  the file that you'd like to write, or an IO-like object.
        def write_pem(filename_or_io)
            write_data(filename_or_io, @cert.to_pem)
        end

        # Writes the Cert into the DER format
        # @param [String, #write] filename_or_io Either a string of the path for
        #  the file that you'd like to write, or an IO-like object.
        def write_der(filename_or_io)
            write_data(filename_or_io, @cert.to_der)
        end

        # Writes cert and key into PKCS12 format using OpenSSL defaults for encryption (des3)
        # @param [String, #write] filename_or_io Either a string of the path for
        #  the file that you'd like to write, or an IO-like object.
        # @param [String] password password
        # @param [String] friendly_name An optional string to encode in the PKCS12 for friendlyName. defaults to "r509 pkcs12"
        def write_pkcs12(filename_or_io,password,friendly_name='r509 pkcs12')
            if @key.nil?
                raise R509::R509Error, "Writing a PKCS12 requires both key and cert"
            end
            pkcs12 = OpenSSL::PKCS12.create(password,friendly_name,@key.key,@cert)
            write_data(filename_or_io, pkcs12.to_der)
        end

        # Return the certificate extensions
        #
        # @return [Array] an array of hashes representing the extensions in the cert
        def extensions
            if @extensions.nil?
                @extensions = Hash.new
                @cert.extensions.to_a.each { |extension|
                    extension = extension.to_a
                    if(!@extensions[extension[0]].kind_of?(Array)) then
                        @extensions[extension[0]] = []
                    end
                    hash = {'value' => extension[1], 'critical' => extension[2]}
                    @extensions[extension[0]].push hash
                }
            end
            @extensions
        end

        # Return the key usage extensions
        #
        # @return [Array] an array containing each KU as a separate string
        def key_usage
            if self.extensions.has_key?("keyUsage") and self.extensions["keyUsage"].count > 0 and self.extensions["keyUsage"][0].has_key?("value")
                self.extensions["keyUsage"][0]["value"].split(",").map{|v| v.strip}
            else
                []
            end
        end

        # Return the extended key usage extensions
        #
        # @return [Array] an array containing each EKU as a separate string
        def extended_key_usage
            if self.extensions.has_key?("extendedKeyUsage") and self.extensions["extendedKeyUsage"].count > 0 and self.extensions["extendedKeyUsage"][0].has_key?("value")
                self.extensions["extendedKeyUsage"][0]["value"].split(",").map{|v| v.strip}
            else
                []
            end
        end

        private
        #takes OpenSSL::X509::Extension object
        def parse_san_extension(extension)
            san_string = extension.to_a[1]
            stripped = san_string.split(',').map{ |name| name.gsub(/DNS:/,'').strip }
            @san_names = stripped
        end

        def parse_certificate(cert)
            @cert = OpenSSL::X509::Certificate.new cert
            @cert.extensions.to_a.each { |extension|
                if (extension.to_a[0] == 'subjectAltName') then
                    parse_san_extension(extension)
                end
            }
        end

    end
end
