require 'openssl'
require 'r509/Exceptions'
require 'r509/io_helpers'

module R509
    # The primary certificate signing request object
    class Csr
    include R509::IOHelpers

        attr_reader :san_names, :key, :subject, :req, :attributes
        def initialize(*args)
            case args.size
                when 0
                    @req = nil
                    @subject = nil
                    @san_names = nil
                    @key = nil
                when 1
                    parse_csr args[0]
                    @key = nil
                when 2
                    parse_csr args[0]
                    @key = OpenSSL::PKey::RSA.new args[1]
                    #verify on the OpenSSL::X509::Request object verifies public key match
                    if !@req.verify(@key.public_key) then
                        raise R509Error, 'Key does not match request.'
                    end
                else
                    raise ArgumentError, 'Too many arguments.'
            end
            self.message_digest='sha1' #default
        end

        # Static method that creates a new CSR using an array as the subject
        # @example
        #   Csr.create_with_subject [['CN','langui.sh'],['ST','Illinois'],['L','Chicago'],['C','US'],['emailAddress','ca@langui.sh']]
        #   You can specify the shortname of any OID that OpenSSL knows.
        # @example
        #   Csr.create_with_subject [['1.3.6.1.4.1.311.60.2.1.3','US'],['2.5.4.7','Chicago'],['emailAddress','ca@langui.sh']]
        #   You can also use OIDs directly (e.g., '1.3.6.1.4.1.311.60.2.1.3')
        # @param subject [Array] subject takes an array of subject items, e.g.
        # @param bit_strength [Integer] bit strength of the private key to generate (default 2048)
        # @param domains [Array] list of domains to encode as subjectAltNames 
        # @return [R509::Csr] the object
        def self.create_with_subject(subject, bit_strength=2048, domains=[])
            csr = Csr.new
            csr.create_with_subject(subject, bit_strength, domains)
            csr
        end

        # Static method that creates a new CSR using an existing certificate as the source for its subject and extensions
        # @param cert [String,OpenSSL::X509::Certificate] certificate data in PEM, DER, or OpenSSL::X509::Certificate form
        # @param bit_strength [Integer] Bit strength of the private key to generate (default 2048)
        # @param domains [Array] List of domains to encode as subjectAltNames
        # @return [R509::Csr] the object
        def self.create_with_cert(cert, bit_strength=2048, domains=[])
            csr = Csr.new
            csr.create_with_cert(cert, bit_strength, domains)
            csr
        end

        # @return [String] message digest friendly name
        def message_digest
            case @message_digest
                when OpenSSL::Digest::SHA1 then 'sha1'
                when OpenSSL::Digest::SHA256 then 'sha256'
                when OpenSSL::Digest::SHA512 then 'sha512'
                when OpenSSL::Digest::MD5 then 'md5'
            end
        end

        # Changes the message digest (must be called before
        # creation of signed object via methods create_with_cert or
        # create_with_subject
        # @param digest [String] New message digest (md5,sha1,sh256,sha512)
        def message_digest=(digest)
            @message_digest = case digest.downcase
                when 'sha1' then OpenSSL::Digest::SHA1.new
                when 'sha256' then OpenSSL::Digest::SHA256.new
                when 'sha512' then OpenSSL::Digest::SHA512.new
                when 'md5' then OpenSSL::Digest::MD5.new
                else OpenSSL::Digest::SHA1.new
            end
        end

        # @return [OpenSSL::PKey::RSA] public key
        def public_key
            if(@req.kind_of?(OpenSSL::X509::Request)) then
                @req.public_key
            end
        end

        # Verifies the integrity of the signature on the request
        # @return [Boolean]
        def verify_signature
            if(@req.kind_of?(OpenSSL::X509::Request)) then
                @req.verify(public_key)
            else
                false
            end
        end

        # Converts the CSR into the PEM format
        #
        # @return [String] the CSR converted into PEM format.
        def to_pem
            if(@req.kind_of?(OpenSSL::X509::Request)) then
                @req.to_pem
            end
        end

        alias :to_s :to_pem

        # Converts the CSR into the DER format
        #
        # @return [String] the CSR converted into DER format.
        def to_der
            if(@req.kind_of?(OpenSSL::X509::Request)) then
                @req.to_der
            end
        end

        # Writes the CSR into the PEM format
        #
        # @param [String, #write] filename_or_io Either a string of the path for
        #  the file that you'd like to write, or an IO-like object.
        def write_pem(filename_or_io)
            write_data(filename_or_io, @req.to_pem)
        end

        # Writes the CSR into the DER format
        #
        # @param [String, #write] filename_or_io Either a string of the path for
        #  the file that you'd like to write, or an IO-like object.
        def write_der(filename_or_io)
            write_data(filename_or_io, @req.to_der)
        end

        # Returns whether the public key is RSA
        #
        # @return [Boolean] true if the public key is RSA, false otherwise
        def rsa?
            @req.public_key.kind_of?(OpenSSL::PKey::RSA)
        end

        # Returns whether the public key is DSA
        #
        # @return [Boolean] true if the public key is DSA, false otherwise
        def dsa?
            @req.public_key.kind_of?(OpenSSL::PKey::DSA)
        end

        # Returns the bit strength of the key used to create the CSR
        # @return [Integer] the integer bit strength.
        def bit_strength
            if !@req.nil?
                if self.rsa?
                    return @req.public_key.n.to_i.to_s(2).size
                elsif self.dsa?
                    return @req.public_key.pub_key.to_i.to_s(2).size
                end
            end
        end

        # Creates a new CSR using an existing certificate as the source for its subject and extensions
        # @param cert [String,OpenSSL::X509::Certificate] certificate data in PEM, DER, or OpenSSL::X509::Certificate form
        # @param bit_strength [Integer] Bit strength of the private key to generate (default 2048)
        # @param domains [Array] List of domains to encode as subjectAltNames
        # @return [R509::Csr] the object
        def create_with_cert(cert,bit_strength=2048,domains=[])
            domains_to_add = []
            san_extension = nil
            parsed_cert = OpenSSL::X509::Certificate.new(cert)
            parsed_cert.extensions.to_a.each { |extension|
                if (extension.to_a[0] == 'subjectAltName') then
                    domains_to_add = parse_san_extension(extension)
                end
            }
            if (domains.kind_of?(Array)) then
                parsed_domains = prefix_domains(domains)
                domains_to_add.concat(parsed_domains).uniq!
            end
            create_csr(parsed_cert.subject,bit_strength,domains_to_add)
            @req.to_pem
        end

        # Creates a new CSR using an array as the subject
        # @example
        #   csr.create_with_subject [['CN','langui.sh'],['ST','Illinois'],['L','Chicago'],['C','US'],['emailAddress','ca@langui.sh']]
        #   You can specify the shortname of any OID that OpenSSL knows.
        # @example
        #   csr.create_with_subject [['1.3.6.1.4.1.311.60.2.1.3','US'],['2.5.4.7','Chicago'],['emailAddress','ca@langui.sh']]
        #   You can also use OIDs directly (e.g., '1.3.6.1.4.1.311.60.2.1.3')
        # @param subject [Array] subject takes an array of subject items, e.g.
        # @param bit_strength [Integer] bit strength of the private key to generate (default 2048)
        # @param domains [Array] list of domains to encode as subjectAltNames (these will be merged with whatever SAN domains are
        #   already present in the CSR
        # @return [R509::Csr] the object
        def create_with_subject(subject,bit_strength=2048,domains=[])
            subject = OpenSSL::X509::Name.new subject
            parsed_domains = prefix_domains(domains)
            create_csr(subject,bit_strength,parsed_domains)
            @req.to_pem
        end

        # Returns subject component
        #
        # @return [String] value of the subject component requested
        def subject_component short_name
            @req.subject.to_a.each do |element|
                if element[0].downcase == short_name.downcase then
                    return element[1]
                end
            end
            nil
        end

        # Returns signature algorithm
        # #
        # # @return [String] value of the signature algorithm. E.g. sha1WithRSAEncryption, sha256WithRSAEncryption, md5WithRSAEncryption
        def signature_algorithm
            @req.signature_algorithm
        end

        # Returns key algorithm (RSA/DSA)
        # #
        # # @return [String] value of the key algorithm. RSA or DSA
        def key_algorithm
            if not @req.nil?
                if @req.public_key.kind_of? OpenSSL::PKey::RSA then
                    'RSA'
                elsif @req.public_key.kind_of? OpenSSL::PKey::DSA then
                    'DSA'
                end
            else
                nil
            end
        end

        private

        def parse_csr(csr)
            @req = OpenSSL::X509::Request.new csr
            @subject = @req.subject
            @attributes = parse_attributes_from_csr @req
            @san_names = @attributes['subjectAltName']
        end

        def create_csr(subject,bit_strength,domains=[])
            @req = OpenSSL::X509::Request.new
            @req.version = 0
            @req.subject = subject
            @key = OpenSSL::PKey::RSA.generate(bit_strength)
            @req.public_key = @key.public_key
            add_san_extension(domains)
            @req.sign(@key, @message_digest)
            @subject = @req.subject
        end

        #takes OpenSSL::X509::Extension object
        def parse_san_extension(extension)
            san_string = extension.to_a[1]
            stripped = []
            san_string.split(',').each{ |name|
                stripped.push name.strip
            }
            stripped
        end

        def add_san_extension(domains_to_add)
            if(domains_to_add.size > 0) then
                ef = OpenSSL::X509::ExtensionFactory.new
                ex = []
                ex << ef.create_extension("subjectAltName", domains_to_add.join(', '))
                request_extension_set = OpenSSL::ASN1::Set([OpenSSL::ASN1::Sequence(ex)])
                @req.add_attribute(OpenSSL::X509::Attribute.new("extReq", request_extension_set))
                @san_names = strip_prefix(domains_to_add)
            end
        end

        def prefix_domains(domains)
            domains.map { |domain| 'DNS: '+domain }
        end

        def strip_prefix(domains)
            domains.map{ |name| name.gsub(/DNS:/,'').strip }
        end

        def parse_attributes_from_csr req
            attributes = Hash.new
            domains_from_csr = []
            set = nil
            req.attributes.each { |attribute|
                if attribute.oid == 'extReq' then
                set = OpenSSL::ASN1.decode attribute.value
                end
            }
            if !set.nil? then
                set.value.each { |set_value|
                    @seq = set_value
                    extensions = @seq.value.collect{|asn1ext| OpenSSL::X509::Extension.new(asn1ext).to_a }
                    extensions.each { |ext|
                        hash = {'value' => ext[1], 'critical'=> ext[2] }
                        attributes[ext[0]] = hash
                        if ext[0] == 'subjectAltName' then
                            domains_from_csr = ext[1].gsub(/DNS:/,'').split(',')
                            domains_from_csr = domains_from_csr.collect {|x| x.strip }
                            attributes[ext[0]] = domains_from_csr
                        end
                    }
                }
            end
            attributes
        end
    end
end
