require 'openssl'
require 'r509/Exceptions'
require 'r509/io_helpers'
require 'r509/PrivateKey'
require 'r509/HelperClasses'

module R509
    # The primary certificate signing request object
    class Csr
        include R509::IOHelpers

        attr_reader :san_names, :key, :subject, :req, :attributes, :message_digest
        # @option opts [String,OpenSSL::X509::Request] :csr a csr
        # @option opts [Symbol] :type :rsa/:dsa
        # @option opts [Integer] :bit_strength
        # @option opts [Array] :domains List of domains to encode as subjectAltNames
        # @option opts [R509::Subject,Array,OpenSSL::X509::Name] :subject array of subject items
        # @example [['CN','langui.sh'],['ST','Illinois'],['L','Chicago'],['C','US'],['emailAddress','ca@langui.sh']]
        # you can also pass OIDs (see tests)
        # @option opts [String,R509::Cert,OpenSSL::X509::Certificate] :cert takes a cert (used for generating a CSR with the certificate's values)
        # @option opts [R509::PrivateKey,String] :key optional private key to supply. either an unencrypted PEM/DER string or an R509::PrivateKey object (use the latter if you need password/hardware support)
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

            if opts.has_key?(:key)
                if opts[:key].kind_of?(R509::PrivateKey)
                    @key = opts[:key]
                else
                    @key = R509::PrivateKey.new(:key => opts[:key])
                end
            end

            @type = opts[:type] || :rsa
            if @type != :rsa and @type != :dsa and @key.nil?
                raise ArgumentError, 'Must provide :rsa or :dsa as type when key is nil'
            end

            if opts.has_key?(:cert)
                domains = opts[:domains] || []
                parsed_domains = prefix_domains(domains)
                cert_data = parse_cert(opts[:cert])
                merged_domains = cert_data[:subjectAltName].concat(parsed_domains)
                create_request(cert_data[:subject],merged_domains) #sets @req
            elsif opts.has_key?(:subject)
                domains = opts[:domains] || []
                parsed_domains = prefix_domains(domains)
                create_request(opts[:subject], parsed_domains) #sets @req
            elsif opts.has_key?(:csr)
                if opts.has_key?(:domains)
                    raise ArgumentError, "You can't add domains to an existing CSR"
                end
                parse_csr(opts[:csr])
            else
                raise ArgumentError, "Must provide one of cert, subject, or csr"
            end

            if dsa?
                #only DSS1 is acceptable for DSA signing in OpenSSL < 1.0
                #post-1.0 you can sign with anything, but let's be conservative
                #see: http://www.ruby-doc.org/stdlib-1.9.3/libdoc/openssl/rdoc/OpenSSL/PKey/DSA.html
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

        # @return [Boolean] Boolean of whether the object contains a private key
        def has_private_key?
            if not @key.nil?
                true
            else
                false
            end
        end

        # Converts the CSR into the PEM format
        #
        # @return [String] the CSR converted into PEM format.
        def to_pem
            @req.to_pem
        end

        alias :to_s :to_pem

        # Converts the CSR into the DER format
        #
        # @return [String] the CSR converted into DER format.
        def to_der
            @req.to_der
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
                return @req.public_key.n.num_bits
            elsif self.dsa?
                return @req.public_key.p.num_bits
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
        #
        # @return [String] value of the signature algorithm. E.g. sha1WithRSAEncryption, sha256WithRSAEncryption, md5WithRSAEncryption
        def signature_algorithm
            @req.signature_algorithm
        end

        # Returns key algorithm (RSA/DSA)
        #
        # @return [String] value of the key algorithm. RSA or DSA
        def key_algorithm
            if @req.public_key.kind_of? OpenSSL::PKey::RSA then
                'RSA'
            elsif @req.public_key.kind_of? OpenSSL::PKey::DSA then
                'DSA'
            end
        end

        # Returns a hash structure you can pass to the Ca.
        # You will want to call this method if you intend to alter the values
        # and then pass them to the Ca class.
        #
        # @return [Hash] :subject and :san_names you can pass to Ca
        def to_hash
            { :subject => @subject.dup , :san_names => @san_names.dup }
        end

        private

        def parse_csr(csr)
            begin
                @req = OpenSSL::X509::Request.new csr
            rescue OpenSSL::X509::RequestError
                #let's try to load this thing by handling a few
                #common error cases
                if csr.kind_of?(String)
                    #normalize line endings (really just for the next replace)
                    csr.gsub!(/\r\n?/, "\n")
                    #remove extraneous newlines
                    csr.gsub!(/^\s*\n/,'')
                    #and leading/trailing whitespace
                    csr.gsub!(/^\s*|\s*$/,'')
                    if not csr.match(/-----BEGIN.+-----/) and csr.match(/MII/)
                        #if csr is probably PEM (MII is the beginning of every base64
                        #encoded DER) then add the wrapping lines if they aren't provided.
                        #tools like Microsoft's xenroll do this.
                        csr = "-----BEGIN CERTIFICATE REQUEST-----\n"+csr+"\n-----END CERTIFICATE REQUEST-----"
                    end
                end
                #and now we try again...
                @req = OpenSSL::X509::Request.new csr
            end
            @subject = R509::Subject.new(@req.subject)
            @attributes = parse_attributes_from_csr(@req) #method from HelperClasses
            @san_names = @attributes['subjectAltName'] || []
        end

        def create_request(subject,domains=[])
            domains.uniq! #de-duplicate the array
            @req = OpenSSL::X509::Request.new
            @req.version = 0
            @subject = R509::Subject.new(subject)
            @req.subject = @subject.name
            if @key.nil?
                @key = R509::PrivateKey.new(:type => @type,
                                            :bit_strength => @bit_strength)
            end
            @req.public_key = @key.public_key
            add_san_extension(domains)
            @attributes = parse_attributes_from_csr(@req) #method from HelperClasses
            @san_names = @attributes['subjectAltName'] || []
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

        # @return [Hash] attributes of a CSR
        def parse_attributes_from_csr(req)
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
