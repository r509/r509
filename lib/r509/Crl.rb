require 'openssl'
require 'r509/Config'
require 'r509/Exceptions'
require 'r509/io_helpers'

module R509
	# Used to generate CRLs
	class Crl
    include R509::IOHelpers

    # TODO : Should we remove this in favor of just having all changes 
    #  being made to the configuration object?
		attr_accessor :validity_hours

		def initialize(config)
      @config = config

      unless @config.kind_of?(R509::Config)
        raise R509Error, "config must be a kind of R509::Config"
      end

      @validity_hours = @config.crl_validity_hours
			@crl = nil
		end

    # Indicates whether the serial number has been revoked, or not.
    #
    # @param [Integer] serial The serial number we want to check
    # @return [Boolean True if the serial number was revoked. False, otherwise.
    def revoked?(serial)
      @config.revoked?(serial)
    end
		
		# Returns the CRL in PEM format
		#
		# @return [String] the CRL in PEM format
		def to_pem
			@crl.to_pem
		end
		
		alias :to_s :to_pem

		# Returns the CRL in DER format
		#
		# @return [String] the CRL in DER format
		def to_der
			@crl.to_der
		end

		# Writes the CRL into the PEM format
		#
		# @param [String, #write] filename_or_io Either a string of the path for 
    #  the file that you'd like to write, or an IO-like object.
		def write_pem(filename_or_io)
      write_data(filename_or_io, @crl.to_pem)
		end

		# Writes the CRL into the PEM format
		#
		# @param [String, #write] filename_or_io Either a string of the path for 
    #  the file that you'd like to write, or an IO-like object.
		def write_der(filename_or_io)
      write_data(filename_or_io, @crl.to_der)
		end

		# Returns the signing time of the CRL
		#
		# @return [Time] when the CRL was signed
		def last_update
			@crl.last_update
		end
		
		# Returns the next update time for the CRL
		#
		# @return [Time] when it will be updated next
		def next_update
			@crl.next_update
		end

		# Adds a certificate to the revocation list. After calling you must call generate_crl to sign a new CRL
		#
		# @param serial [Integer] serial number of the certificate to revoke
		# @param reason [Integer] reason for revocation
		#
		#	reason codes defined by rfc 5280
		#	CRLReason ::= ENUMERATED {
		#	      unspecified             (0),
		#	      keyCompromise           (1),
		#	      cACompromise            (2),
		#	      affiliationChanged      (3),
		#	      superseded              (4),
		#	      cessationOfOperation    (5),
		#	      certificateHold         (6),
		#	      removeFromCRL           (8),
		#	      privilegeWithdrawn      (9),
		#	      aACompromise           (10) }
		def revoke_cert(serial,reason=nil)
      if !reason.nil? and !reason.to_i.between?(1,10)
        reason = nil
      end

      @config.revoke_cert(serial, reason.to_i, Time.now)
      @config.save_crl_list()
		end

		# Remove serial from revocation list. After unrevoking you must call generate_crl to sign a new CRL
		#
		# @param serial [Integer] serial number of the certificate to remove from revocation
		def unrevoke_cert(serial)
      @config.unrevoke_cert(serial)
      @config.save_crl_list()
		end

		# Remove serial from revocation list
		#
		# @return [String] PEM encoded signed CRL
		def generate_crl
			crl = OpenSSL::X509::CRL.new
			crl.version = 1
			now = Time.at Time.now.to_i
			crl.last_update = now
			crl.next_update = now+@validity_hours*3600

      @config.revoked_certs.each do |serial, reason, revoke_time|
				revoked = OpenSSL::X509::Revoked.new
				revoked.serial = OpenSSL::BN.new serial.to_s
				revoked.time = Time.at(revoke_time)
				if !reason.nil?
					enum = OpenSSL::ASN1::Enumerated(reason) #see reason codes below
					ext = OpenSSL::X509::Extension.new("CRLReason", enum)
					revoked.add_extension(ext)
				end
				#now add it to the crl
				crl.add_revoked(revoked)
      end
			
			ef = OpenSSL::X509::ExtensionFactory.new
			ca_cert = @config.ca_cert
			ca_key = @config.ca_key
			ef.issuer_certificate = ca_cert
			ef.crl = crl
			#grab crl number from file, increment, write back
			crl_number = @config.increment_crl_number
      @config.save_crl_number()
			crlnum = OpenSSL::ASN1::Integer(crl_number)
			crl.add_extension(OpenSSL::X509::Extension.new("crlNumber", crlnum))
			extensions = []
			extensions << ["authorityKeyIdentifier", "keyid:always,issuer:always", false]
			extensions.each{|oid, value, critical|
				crl.add_extension(ef.create_extension(oid, value, critical))
			}
			crl.sign(ca_key, OpenSSL::Digest::SHA1.new)
			@crl = crl
			@crl.to_pem
		end
	end
end

