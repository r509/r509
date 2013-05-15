require 'openssl'
require 'r509/exceptions'
require 'r509/io_helpers'
require 'r509/private_key'
require 'r509/ec-hack'
require 'r509/asn1'

module R509
  # The primary certificate signing request object
  class CSR
    include R509::IOHelpers

    attr_reader :san, :key, :subject, :req, :attributes, :message_digest
    # @option opts [String,OpenSSL::X509::Request] :csr a csr
    # @option opts [Symbol] :type :rsa/:dsa/:ec required if not providing existing :csr. Defaults to :rsa
    # @option opts [String] :curve_name ("secp384r1") Only used if :type is :ec
    # @option opts [Integer] :bit_strength (2048) Only used if :type is :rsa or :dsa
    # @option opts [String] :message_digest Optional digest. sha1, sha224, sha256, sha384, sha512, md5. Defaults to sha1
    # @option opts [Array,R509::ASN1::GeneralNames] :san_names List of domains, IPs, email addresses, or URIs to encode as subjectAltNames. The type is determined from the structure of the strings via the R509::ASN1.general_name_parser method. You can also pass an explicit R509::ASN1::GeneralNames object
    # @option opts [R509::Subject,Array,OpenSSL::X509::Name] :subject array of subject items
    # @option opts [R509::PrivateKey,String] :key optional private key to supply. either an unencrypted PEM/DER string or an R509::PrivateKey object (use the latter if you need password/hardware support)
    # @example Generate a 4096-bit RSA key + CSR
    #   :type => :rsa,
    #   :bit_strength => 4096,
    #   :subject => [
    #     ['CN','somedomain.com'],
    #     ['O','My Org'],
    #     ['L','City'],
    #     ['ST','State'],
    #     ['C','US']
    #   ]
    # @example Generate an ECDSA key using the secp384r1 curve parameters + CSR and sign with SHA512
    #   :type => :ec,
    #   :curve_name => 'secp384r1',
    #   :message_digest => 'sha512',
    #   :subject => [
    #     ['CN','somedomain.com'],
    #   ]
    def initialize(opts={})
      if not opts.kind_of?(Hash)
        raise ArgumentError, 'Must provide a hash of options'
      end
        if opts.has_key?(:subject) and opts.has_key?(:csr)
        raise ArgumentError, "You must provide :subject or :csr, not both"
      end
      @bit_strength = opts[:bit_strength] || 2048
      @curve_name = opts[:curve_name] || "secp384r1"

      if opts.has_key?(:key)
        if opts[:key].kind_of?(R509::PrivateKey)
          @key = opts[:key]
        else
          @key = R509::PrivateKey.new(:key => opts[:key])
        end
      end

      @type = opts[:type] || :rsa
      if not [:rsa,:dsa,:ec].include?(@type) and @key.nil?
        raise ArgumentError, 'Must provide :rsa, :dsa, or :ec as type when key is nil'
      end

      if opts.has_key?(:subject)
        san_names = R509::ASN1.general_name_parser(opts[:san_names] || [])
        create_request(opts[:subject], san_names) #sets @req
      elsif opts.has_key?(:csr)
        if opts.has_key?(:san_names)
          raise ArgumentError, "You can't add domains to an existing CSR"
        end
        parse_csr(opts[:csr])
      else
        raise ArgumentError, "You must provide :subject or :csr"
      end

      if dsa?
        #only DSS1 is acceptable for DSA signing in OpenSSL < 1.0
        #post-1.0 you can sign with anything, but let's be conservative
        #see: http://www.ruby-doc.org/stdlib-1.9.3/libdoc/openssl/rdoc/OpenSSL/PKey/DSA.html
        @message_digest = R509::MessageDigest.new('dss1')
      else
        @message_digest = R509::MessageDigest.new(opts[:message_digest])
      end

      if not opts.has_key?(:csr)
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
    def self.load_from_file( filename )
      return R509::CSR.new(:csr => IOHelpers.read_data(filename) )
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

    # Returns whether the public key is EC
    #
    # @return [Boolean] true if the public key is EC, false otherwise
    def ec?
      @req.public_key.kind_of?(OpenSSL::PKey::EC)
    end

    # Returns the bit strength of the key used to create the CSR
    # @return [Integer] the integer bit strength.
    def bit_strength
      if self.rsa?
        return @req.public_key.n.num_bits
      elsif self.dsa?
        return @req.public_key.p.num_bits
      elsif self.ec?
        raise R509::R509Error, 'Bit strength is not available for EC at this time.'
      end
    end

    # Returns the short name of the elliptic curve used to generate the public key
    # if the key is EC. If not, raises an error.
    #
    # @return [String] elliptic curve name
    def curve_name
      if self.ec?
        self.public_key.group.curve_name
      else
        raise R509::R509Error, 'Curve name is only available with EC CSRs'
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

    # Returns key algorithm (RSA/DSA/EC)
    #
    # @return [Symbol] value of the key algorithm. :rsa, :dsa, :ec
    def key_algorithm
      if @req.public_key.kind_of? OpenSSL::PKey::RSA then
        :rsa
      elsif @req.public_key.kind_of? OpenSSL::PKey::DSA then
        :dsa
      elsif @req.public_key.kind_of? OpenSSL::PKey::EC then
        :ec
      end
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
      parse_san_attribute_from_csr(@req)
    end

    def create_request(subject,san_names)
      @req = OpenSSL::X509::Request.new
      @req.version = 0
      @subject = R509::Subject.new(subject)
      @req.subject = @subject.name
      if @key.nil?
        @key = R509::PrivateKey.new(:type => @type, :bit_strength => @bit_strength, :curve_name => @curve_name)
      end
      @req.public_key = @key.public_key
      add_san_extension(san_names)
      parse_san_attribute_from_csr(@req)
    end

    # @return [Array] array of GeneralName objects
    def parse_san_attribute_from_csr(req)
      san = nil
      set = nil
      req.attributes.each do |attribute|
        if attribute.oid == 'extReq'
          set = OpenSSL::ASN1.decode attribute.value
          extensions = set.value[0].value.collect{|asn1ext| OpenSSL::X509::Extension.new(asn1ext) }
          r509_extensions = R509::Cert::Extensions.wrap_openssl_extensions( extensions )
          if not r509_extensions[R509::Cert::Extensions::SubjectAlternativeName].nil?
            san = r509_extensions[R509::Cert::Extensions::SubjectAlternativeName].general_names
          end
          break
        end
      end
      @san = san
    end

    def add_san_extension(san_names)
      if not san_names.nil? and not san_names.names.empty?
        names = san_names.names.uniq
        general_names = R509::ASN1::GeneralNames.new
        names.each do |domain|
          general_names.add_item(domain)
        end
        ef = OpenSSL::X509::ExtensionFactory.new
        serialized = general_names.serialize_names
        ef.config = OpenSSL::Config.parse(serialized[:conf])
        ex = []
        ex << ef.create_extension("subjectAltName", serialized[:extension_string])
        request_extension_set = OpenSSL::ASN1::Set([OpenSSL::ASN1::Sequence(ex)])
        @req.add_attribute(OpenSSL::X509::Attribute.new("extReq", request_extension_set))
        parse_san_attribute_from_csr(@req)
      end
    end


  end
end
