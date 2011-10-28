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

		# Returns the bit strength of the key used to create the CSR
		# @return [Integer] the integer bit strength.
		def bit_strength
			if !@req.nil?
				#cast to int, convert to binary, count size
				@req.public_key.n.to_i.to_s(2).size
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
		# 	csr.create_with_subject [['CN','langui.sh'],['ST','Illinois'],['L','Chicago'],['C','US'],['emailAddress','ca@langui.sh']]
		#	You can specify the shortname of any OID that OpenSSL knows.
		# @example 
		# 	csr.create_with_subject [['1.3.6.1.4.1.311.60.2.1.3','US'],['2.5.4.7','Chicago'],['emailAddress','ca@langui.sh']]
		#	You can also use OIDs directly (e.g., '1.3.6.1.4.1.311.60.2.1.3')
		# @param subject [Array] subject takes an array of subject items, e.g.
		# @param bit_strength [Integer] bit strength of the private key to generate (default 2048)
		# @param domains [Array] list of domains to encode as subjectAltNames (these will be merged with whatever SAN domains are 
		#	already present in the CSR
		# @return [R509::Csr] the object
		def create_with_subject(subject,bit_strength=2048,domains=[])
			subject = OpenSSL::X509::Name.new subject
			parsed_domains = prefix_domains(domains)
			create_csr(subject,bit_strength,parsed_domains)
			@req.to_pem
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
			@req.sign(@key, OpenSSL::Digest::SHA1.new)
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
