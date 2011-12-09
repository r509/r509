require 'openssl'
require 'r509/Exceptions'
require 'r509/io_helpers'
require 'r509/PrivateKey'
require 'r509/HelperClasses'

module R509
    # The primary certificate signing request object
    class Csr
        include R509::IOHelpers
        include R509::Helper::CsrHelper

        attr_reader :san_names, :key, :subject, :req, :attributes, :message_digest
        # @option opts [String,OpenSSL::X509::Request] :csr a csr
        # @option opts [Symbol] :type :rsa/:dsa
        # @option opts [Integer] :bit_strength
        # @option opts [String] :password
        # @option opts [Array] :domains List of domains to encode as subjectAltNames
        # @option opts [Array,OpenSSL::X509::Name] :subject array of subject items
        # @example [['CN','langui.sh'],['ST','Illinois'],['L','Chicago'],['C','US'],['emailAddress','ca@langui.sh']]
        # you can also pass OIDs (see tests)
        # @option opts [String,R509::Cert,OpenSSL::X509::Certificate] :cert takes a cert (used for generating a CSR with the certificate's values)
        # @option opts [String,OpenSSL::PKey::RSA,OpenSSL::PKey::DSA] :key
        def initialize(opts={})
            if not opts.kind_of?(Hash)
                raise ArgumentError, 'Must provide a hash of options'
            end
            if (opts.has_key?(:cert) and opts.has_key?(:subject)) or
                (opts.has_key?(:cert) and opts.has_key?(:csr)) or
                (opts.has_key?(:subject) and opts.has_key?(:csr))
                raise ArgumentError, "Can only provide one of cert, subject, or csr"
            end
            @bit_strength = opts[:bit_strength] || 2048
            password = opts[:password] || nil

            if opts.has_key?(:key)
                @key = R509::PrivateKey.new(:key => opts[:key], :password => password)
            end

            @type = opts[:type] || :rsa
            if @type != :rsa and @type != :dsa and @key.nil?
                raise ArgumentError, 'Must provide :rsa or :dsa as type when key is nil'
            end

            if opts.has_key?(:cert)
                cert_data = parse_cert(opts[:cert])
                create_request(cert_data[:subject],cert_data[:subjectAltName]) #sets @req
            elsif opts.has_key?(:subject)
                domains = opts[:domains] || []
                subject = OpenSSL::X509::Name.new(opts[:subject])
                parsed_domains = prefix_domains(domains)
                create_request(subject,parsed_domains) #sets @req
            elsif opts.has_key?(:csr)
                parse_csr(opts[:csr])
            else
                raise ArgumentError, "Must provide one of cert, subject, or csr"
            end

            if dsa?
                @message_digest = R509::MessageDigest.new('dss1')
            elsif opts.has_key?(:message_digest)
                @message_digest = R509::MessageDigest.new(opts[:message_digest])
            else
                @message_digest = R509::MessageDigest.new('sha1')
            end

            if not opts.has_key?(:csr)
                @req.sign(@key.key, @message_digest.digest)
            end
            if not @key.nil? and not @req.verify(@key.public_key) then
                raise R509Error, 'Key does not match request.'
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
            @req.verify(public_key)
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
            if self.rsa?
                return @req.public_key.n.to_i.to_s(2).size
            elsif self.dsa?
                return @req.public_key.p.to_i.to_s(2).size
            end
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
            @attributes = parse_attributes_from_csr(@req) #method from HelperClasses
            @san_names = @attributes['subjectAltName']
        end

        def create_request(subject,domains=[])
            @req = OpenSSL::X509::Request.new
            @req.version = 0
            @req.subject = subject
            if @key.nil?
                @key = R509::PrivateKey.new(:type => @type,
                                            :bit_strength => @bit_strength)
            end
            @req.public_key = @key.public_key
            add_san_extension(domains)
            @attributes = parse_attributes_from_csr(@req) #method from HelperClasses
            @san_names = @attributes['subjectAltName']
            @subject = @req.subject
        end

        # parses an existing cert to get data to add to new CSR
        def parse_cert(cert)
            domains_to_add = []
            san_extension = nil
            parsed_cert = OpenSSL::X509::Certificate.new(cert)
            parsed_cert.extensions.to_a.each { |extension|
                if (extension.to_a[0] == 'subjectAltName') then
                    domains_to_add = parse_san_extension(extension)
                end
            }
            {:subject => parsed_cert.subject, :subjectAltName => domains_to_add}
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
    end
end
