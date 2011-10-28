require 'openssl'
require 'yaml'
require 'r509/Exceptions'
require 'r509/io_helpers'

module R509
	# Used to generate CRLs
	class Crl
    include R509::IOHelpers

		attr_reader :revoked_list
		attr_accessor :validity_hours
		def initialize(ca)
			if(File.exists?('~/.r509.yaml')) then
				file = File.read('~/.r509.yaml')
				test_ca = false
			else
				file = File.read(File.dirname(__FILE__)+'/../../r509.yaml')
				test_ca = true
			end
		
			config = YAML::load(file)
			@config = config[ca]
			if test_ca then
				@config['ca_cert'] = File.dirname(__FILE__)+'/../../'+@config['ca_cert']
				@config['ca_key'] = File.dirname(__FILE__)+'/../../'+@config['ca_key']
				@config['crl_list'] = File.dirname(__FILE__)+'/../../'+@config['crl_list']
				@config['crl_number'] = File.dirname(__FILE__)+'/../../'+@config['crl_number']
			end
			@crl = nil
			@revoked_list = nil
			@validity_hours = @config['crl_validity_hours']
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
			#should probably check to make sure the values passed are sane
			now = Time.now.to_i
			line = [serial,now]
			if(0 <= reason.to_i && reason.to_i <= 10) then
				line.push reason.to_i
			end
			line = line.join(',')
			open(@config['crl_list'], 'a') { |f|
				f.puts line
			}
		end

		# Remove serial from revocation list. After unrevoking you must call generate_crl to sign a new CRL
		#
		# @param serial [Integer] serial number of the certificate to remove from revocation
		def unrevoke_cert(serial)
			#come back around and do this better
			list = File.readlines(@config['crl_list'])
			regex = Regexp.new("^"+serial.to_s+",.*") #comma ensures we don't capture a substring of a longer serial accidentally
			list.delete_if { |line|
				line.match(regex)
			}
			open(@config['crl_list'],'w') { |f| 
				f.puts list.join
			}
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

			revocation_list = []
			@revoked_list = [] #empty it out
			File.open(@config['crl_list']).each { |line|
				revocation_data = line.chomp.split(',')
				revoked = OpenSSL::X509::Revoked.new
				revoked.serial = OpenSSL::BN.new revocation_data[0].to_s
				revoked.time = Time.at(revocation_data[1].to_i)
				@revoked_list.push({'serial'=>revocation_data[0].to_i,'time'=>Time.at(revocation_data[1].to_i),'reason'=>revocation_data[2]})
				if(revocation_data.size > 2) then
					reason_code = revocation_data[2].to_i
					enum = OpenSSL::ASN1::Enumerated(reason_code) #see reason codes below
					ext = OpenSSL::X509::Extension.new("CRLReason", enum)
					revoked.add_extension(ext)
				end
				#now add it to the crl
				crl.add_revoked(revoked)
			}
			ef = OpenSSL::X509::ExtensionFactory.new
			ca_cert = OpenSSL::X509::Certificate.new File.read(@config['ca_cert'])
			ca_key = OpenSSL::PKey::RSA.new File.read(@config['ca_key'])
			ef.issuer_certificate = ca_cert
			ef.crl = crl
			#grab crl number from file, increment, write back
			crl_number = File.read(@config['crl_number'])
			crl_number = crl_number.to_i + 1;
			open(@config['crl_number'],'w') { |f| f.puts(crl_number) }
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

