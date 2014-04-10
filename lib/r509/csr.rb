require 'openssl'
require 'r509/exceptions'
require 'r509/io_helpers'
require 'r509/helpers'
require 'r509/private_key'
require 'r509/ec-hack'
require 'r509/asn1'

module R509
  # The primary certificate signing request object
  class CSR
    include R509::IOHelpers
    include R509::Helpers

    attr_reader :san, :key, :subject, :req, :attributes, :message_digest
    # @option opts [String,OpenSSL::X509::Request] :csr a csr
    # @option opts [String] :type Required if not providing existing :csr. Defaults to R509::PrivateKey::DEFAULT_TYPE. Allows R509::PrivateKey::KNOWN_TYPES.
    # @option opts [String] :curve_name ("secp384r1") Only used if :type is EC
    # @option opts [Integer] :bit_length (2048) Only used if :type is RSA or DSA
    # @option opts [Integer] :bit_strength (2048) Deprecated, identical to bit_length.
    # @option opts [String] :message_digest Optional digest. sha1, sha224, sha256, sha384, sha512, md5. Defaults to sha1
    # @option opts [Array,R509::ASN1::GeneralNames] :san_names List of domains, IPs, email addresses, or URIs to encode as subjectAltNames. The type is determined from the structure of the strings via the R509::ASN1.general_name_parser method. You can also pass an explicit R509::ASN1::GeneralNames object. Parsed names will be uniqued, but a GeneralNames object will not be touched.
    # @option opts [R509::Subject,Array,OpenSSL::X509::Name] :subject array of subject items
    # @option opts [R509::PrivateKey,String] :key optional private key to supply. either an unencrypted PEM/DER string or an R509::PrivateKey object (use the latter if you need password/hardware support)
    # @example Generate a 4096-bit RSA key + CSR
    #   :type => "RSA",
    #   :bit_length => 4096,
    #   :subject => [
    #     ['CN','somedomain.com'],
    #     ['O','My Org'],
    #     ['L','City'],
    #     ['ST','State'],
    #     ['C','US']
    #   ]
    # @example Generate a 2048-bit RSA key + CSR
    #   :type => "RSA",
    #   :bit_length => 4096,
    #   :subject => { :CN => "myCN", :O => "org" }
    # @example Generate an ECDSA key using the secp384r1 curve parameters + CSR and sign with SHA512
    #   :type => "EC",
    #   :curve_name => 'secp384r1',
    #   :message_digest => 'sha512',
    #   :subject => [
    #     ['CN','somedomain.com'],
    #   ]
    def initialize(opts={})
      unless opts.kind_of?(Hash)
        raise ArgumentError, 'Must provide a hash of options'
      end
      if opts.key?(:subject) and opts.key?(:csr)
        raise ArgumentError, "You must provide :subject or :csr, not both"
      end
      @bit_length = opts[:bit_length] || opts[:bit_strength] || R509::PrivateKey::DEFAULT_STRENGTH
      @curve_name = opts[:curve_name] || R509::PrivateKey::DEFAULT_CURVE

      @key = load_private_key(opts)

      @type = opts[:type] || R509::PrivateKey::DEFAULT_TYPE
      if not R509::PrivateKey::KNOWN_TYPES.include?(@type.upcase) and @key.nil?
        raise ArgumentError, "Must provide #{R509::PrivateKey::KNOWN_TYPES.join(", ")} as type when key is nil"
      end

      if opts.key?(:subject)
        san_names = R509::ASN1.general_name_parser(opts[:san_names])
        create_request(opts[:subject], san_names) # sets @req
      elsif opts.key?(:csr)
        if opts.key?(:san_names)
          raise ArgumentError, "You can't add domains to an existing CSR"
        end
        parse_csr(opts[:csr])
      else
        raise ArgumentError, "You must provide :subject or :csr"
      end

      if dsa?
        # only DSS1 is acceptable for DSA signing in OpenSSL < 1.0
        # post-1.0 you can sign with anything, but let's be conservative
        # see: http://www.ruby-doc.org/stdlib-1.9.3/libdoc/openssl/rdoc/OpenSSL/PKey/DSA.html
        @message_digest = R509::MessageDigest.new('dss1')
      else
        @message_digest = R509::MessageDigest.new(opts[:message_digest])
      end

      unless opts.key?(:csr)
        @req.sign(@key.key, @message_digest.digest)
      end
      if not @key.nil? and not @req.verify(@key.public_key) then
        raise R509Error, 'Key does not match request.'
      end
    end

    # Helper method to quickly load a CSR from the filesystem
    #
    # @param [String] filename Path to file you want to load
    # @return [R509::CSR] CSR object
    def self.load_from_file(filename)
      return R509::CSR.new(:csr => IOHelpers.read_data(filename))
    end

    # @return [OpenSSL::PKey::RSA,OpenSSL::PKey::DSA,OpenSSL::PKey::EC] public key
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

    alias_method :to_s, :to_pem

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

    # Returns key algorithm (RSA/DSA/EC)
    #
    # @return [String] value of the key algorithm. RSA, DSA, or EC
    def key_algorithm
      if @req.public_key.kind_of? OpenSSL::PKey::RSA then
        "RSA"
      elsif @req.public_key.kind_of? OpenSSL::PKey::DSA then
        "DSA"
      elsif @req.public_key.kind_of? OpenSSL::PKey::EC then
        "EC"
      end
    end

    private

    def parse_csr(csr)
      begin
        @req = OpenSSL::X509::Request.new csr
      rescue OpenSSL::X509::RequestError
        # let's try to load this thing by handling a few
        # common error cases
        if csr.kind_of?(String)
          # normalize line endings (really just for the next replace)
          csr.gsub!(/\r\n?/, "\n")
          # remove extraneous newlines
          csr.gsub!(/^\s*\n/,'')
          # and leading/trailing whitespace
          csr.gsub!(/^\s*|\s*$/,'')
          if not csr.match(/-----BEGIN.+-----/) and csr.match(/MII/)
            # if csr is probably PEM (MII is the beginning of every base64
            # encoded DER) then add the wrapping lines if they aren't provided.
            # tools like Microsoft's xenroll do this.
            csr = "-----BEGIN CERTIFICATE REQUEST-----\n"+csr+"\n-----END CERTIFICATE REQUEST-----"
          end
        end
        # and now we try again...
        @req = OpenSSL::X509::Request.new csr
      end
      @subject = R509::Subject.new(@req.subject)
      parse_san_attribute_from_csr(@req)
    end

    def create_request(subject,san_names)
      @req = OpenSSL::X509::Request.new
      @req.version = 0
      @subject = R509::Subject.new(subject)
      @req.subject = @subject.name
      if @key.nil?
        @key = R509::PrivateKey.new(:type => @type, :bit_length => @bit_length, :curve_name => @curve_name)
      end
      @req.public_key = @key.public_key
      add_san_extension(san_names)
    end

    # @return [Array] array of GeneralName objects
    def parse_san_attribute_from_csr(req)
      req.attributes.each do |attribute|
        if attribute.oid == 'extReq'
          set = OpenSSL::ASN1.decode attribute.value
          extensions = set.value[0].value.map{|asn1ext| OpenSSL::X509::Extension.new(asn1ext) }
          r509_extensions = R509::Cert::Extensions.wrap_openssl_extensions(extensions)
          unless r509_extensions[R509::Cert::Extensions::SubjectAlternativeName].nil?
            @san = r509_extensions[R509::Cert::Extensions::SubjectAlternativeName].general_names
          end
          break
        end
      end
    end

    def add_san_extension(san_names)
      if san_names.kind_of?(R509::ASN1::GeneralNames) and not san_names.names.empty?
        ef = OpenSSL::X509::ExtensionFactory.new
        serialized = san_names.serialize_names
        ef.config = OpenSSL::Config.parse(serialized[:conf])
        ex = []
        ex << ef.create_extension("subjectAltName", serialized[:extension_string])
        request_extension_set = OpenSSL::ASN1::Set([OpenSSL::ASN1::Sequence(ex)])
        @req.add_attribute(OpenSSL::X509::Attribute.new("extReq", request_extension_set))
        parse_san_attribute_from_csr(@req)
      end
    end

    def internal_obj
      @req
    end
  end
end
