require 'openssl'
require 'r509/config'
require 'r509/cert'
require 'r509/exceptions'
require 'r509/ec-hack'

# CertificateAuthority related classes
module R509::CertificateAuthority
  # Contains the certification authority signing operation methods
  class Signer
    # @param [R509::Config] config
    def initialize(config)
      @config = config

      if not @config.nil? and not @config.kind_of?(R509::Config::CAConfig)
        raise R509::R509Error, "config must be a kind of R509::Config::CAConfig"
      end
      if not @config.nil? and not @config.ca_cert.has_private_key?
        raise R509::R509Error, "You must have a private key associated with your CA certificate to issue"
      end
    end

    # Signs a CSR
    # @option options :csr [R509::CSR]
    # @option options :spki [R509::SPKI]
    # @option options :subject [R509::Subject,OpenSSL::X509::Subject,Array] This is optional when passing a :csr but required for :spki
    # @option options :message_digest [String] the message digest to use for this certificate instead of the default (see R509::MessageDigest::DEFAULT_MD).
    # @option options :serial [String] (random serial) the serial number you want to issue the certificate with
    # @option options :extensions [Array] An array of R509::Cert::Extensions::* objects that represent the extensions you want to embed in the final certificate
    # @option options :not_before [Time] (Time.now - 6 hours) the notBefore for the certificate
    # @option options :not_after [Time] (Time.now + 365 days) the notAfter for the certificate
    # @return [R509::Cert] the signed cert object
    def sign(options)
      R509::CertificateAuthority::Signer.check_options(options)

      message_digest = R509::MessageDigest.new(options[:message_digest])

      subject, public_key = R509::CertificateAuthority::Signer.extract_public_key_subject(options)

      cert = R509::CertificateAuthority::Signer.build_cert(
        :subject => subject.name,
        :issuer => @config.ca_cert.subject.name,
        :not_before => options[:not_before],
        :not_after => options[:not_after],
        :public_key => public_key,
        :serial => options[:serial]
      )

      cert.extensions = options[:extensions] || [
        R509::Cert::Extensions::SubjectKeyIdentifier.new(:public_key => public_key),
        R509::Cert::Extensions::AuthorityKeyIdentifier.new(:public_key => @config.ca_cert.public_key)
      ]

      # @config.ca_cert.key.key ... ugly. ca_cert returns R509::Cert
      # #key returns R509::PrivateKey and #key on that returns OpenSSL object we need
      cert.sign(@config.ca_cert.key.key, message_digest.digest)
      cert_opts = { :cert => cert }
      cert_opts[:key] = options[:csr].key if not options[:csr].nil? and not options[:csr].key.nil?
      R509::Cert.new(cert_opts)
    end

    # Self-signs a CSR
    # @option options :csr [R509::CSR]
    # @option options :message_digest [String] the message digest to use for this certificate (defaults to R509::MessageDigest::DEFAULT_MD)
    # @option options :serial [String] (random serial) the serial number you want to issue the certificate with
    # @option options :extensions [Array] An array of R509::Cert::Extensions::* objects that represent the extensions you want to embed in the final certificate
    # @option options :not_before [Time] (Time.now - 6 hours) the notBefore for the certificate
    # @option options :not_after [Time] (Time.now + 365 days) the notAfter for the certificate
    # @return [R509::Cert] the signed cert object
    def self.selfsign(options)
      unless options.kind_of?(Hash)
        raise ArgumentError, "You must pass a hash of options consisting of at minimum :csr"
      end
      csr = options[:csr]
      if csr.key.nil?
        raise ArgumentError, 'CSR must also have a private key to self sign'
      end

      subject, public_key = R509::CertificateAuthority::Signer.extract_public_key_subject(options)

      cert = self.build_cert(
        :subject => subject.name,
        :issuer => subject.name,
        :not_before => options[:not_before],
        :not_after => options[:not_after],
        :public_key => public_key,
        :serial => options[:serial]
      )

      cert.extensions = options[:extensions] || [
        R509::Cert::Extensions::BasicConstraints.new(:ca => true),
        R509::Cert::Extensions::SubjectKeyIdentifier.new(:public_key => public_key),
        R509::Cert::Extensions::AuthorityKeyIdentifier.new(:public_key => public_key)
      ]

      if options.key?(:message_digest)
        message_digest = R509::MessageDigest.new(options[:message_digest])
      else
        message_digest = R509::MessageDigest.new(R509::MessageDigest::DEFAULT_MD)
      end

      cert.sign(csr.key.key, message_digest.digest)

      R509::Cert.new(:cert => cert, :key => csr.key)
    end

    private

    def self.check_options(options)
      if options.key?(:csr) and options.key?(:spki)
        raise ArgumentError, "You can't pass both :csr and :spki"
      elsif not options.key?(:csr) and not options.key?(:spki)
        raise ArgumentError, "You must supply either :csr or :spki"
      elsif options.key?(:csr) and not options[:csr].kind_of?(R509::CSR)
        raise ArgumentError, "You must pass an R509::CSR object for :csr"
      elsif options.key?(:spki) and not options[:spki].kind_of?(R509::SPKI)
        raise ArgumentError, "You must pass an R509::SPKI object for :spki"
      end
    end

    def self.build_cert(options)
      cert = OpenSSL::X509::Certificate.new

      cert.subject = options[:subject]
      cert.issuer = options[:issuer]
      cert.not_before = calculate_not_before(options[:not_before])
      cert.not_after = calculate_not_after(options[:not_after],cert.not_before)
      cert.public_key = options[:public_key]
      cert.serial = create_serial(options[:serial])
      cert.version = 2 # 2 means v3
      cert
    end

    def self.create_serial(serial)
      if not serial.nil?
        serial = OpenSSL::BN.new(serial.to_s)
      else
        # generate random serial in accordance with best practices
        #
        # guidelines state 20-bits of entropy, but we can cram more in!
        # per rfc5280 conforming CAs can make the serial field up to 20 octets
        # to prevent even the incredibly remote possibility of collision we'll
        # concatenate current time (to the microsecond) with a random num
        rand = OpenSSL::BN.rand(96,0) # 96 bits is 12 bytes (octets).
        serial = OpenSSL::BN.new((Time.now.to_f*1000000).to_i.to_s + rand.to_s)
        # since second param is 0 the most significant bit must always be 1
        # this theoretically gives us 95 bits of entropy
        # (see: http://www.openssl.org/docs/crypto/BN_rand.html) + microtime,
        # which adds a non-zero quantity of entropy. depending upon how predictable
        # your issuance is, this could range from a reasonably large quantity
        # of entropy to very little
      end
      serial
    end

    def self.calculate_not_before(not_before)
      if not_before.nil?
        # not_before will be set to 6 hours before now to prevent issues with bad system clocks (clients don't sync)
        not_before = Time.now - 6 * 60 * 60
      end
      not_before
    end

    def self.calculate_not_after(not_after,not_before)
      if not_after.nil?
        not_after = not_before + 365 * 24 * 60 * 60
      end
      not_after
    end

    def self.extract_public_key_subject(options)
      if options.key?(:csr)
        subject = (options.key?(:subject))? R509::Subject.new(options[:subject]) : options[:csr].subject
        public_key = options[:csr].public_key
      else
        # spki
        unless options.key?(:subject)
          raise ArgumentError, "You must supply :subject when passing :spki"
        end
        public_key = options[:spki].public_key
        subject = R509::Subject.new(options[:subject])
      end

      [subject,public_key]
    end
  end
end
