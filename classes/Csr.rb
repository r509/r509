require 'openssl'

class Csr
	attr_reader :san_names, :key, :bit_strength
	def initialize
		@req = nil
		@san_names = nil
		@bit_strength = nil
		@key = nil
	end

	def to_pem
		if(@req.kind_of?(OpenSSL::X509::Request)) then
			@req.to_pem
		end
	end

	alias :to_s :to_pem

	def to_der
		if(@req.kind_of?(OpenSSL::X509::Request)) then
			@req.to_der
		end
	end

	def subject
		if(@req.kind_of?(OpenSSL::X509::Request)) then
			@req.subject.to_a
		end
	end

	#string pem
	#int bit_strength
	#array domains
	def create_csr_from_cert(pem,bit_strength=2048,domains=[])
		domains_to_add = []
		san_extension = nil
		cert = OpenSSL::X509::Certificate.new(pem)
		cert.extensions.to_a.each { |extension| 
			if (extension.to_a[0] == 'subjectAltName') then
				domains_to_add = parse_san_extension(extension)
			end
		}
		if (domains.kind_of?(Array)) then
			parsed_domains = []
			domains.each { |domain| 
				parsed_domains.push('DNS: '+domain)
			}
			domains_to_add.concat(parsed_domains).uniq!
		end
		#name = OpenSSL::X509::Name.new(cert.subject.to_a) #this creates a new name object using an array
		create_csr(cert.subject,bit_strength,domains_to_add)
		@req.to_pem
	end

	#todo
	def create_csr_with_subject(subject,bit_strength,domains=[])
		#do something with the subject array...?
		create_csr('',bit_strength,domains)

	end

	private

	def create_csr(subject,bit_strength,domains=[])
		req = OpenSSL::X509::Request.new
		req.version = 0
		req.subject = subject
		@key = OpenSSL::PKey::RSA.generate(bit_strength)
		@bit_strength = bit_strength
		req.public_key = @key.public_key
		add_san_extension(req,domains)
		req.sign(@key, OpenSSL::Digest::SHA1.new)
		@req = req
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

	def add_san_extension(req,domains_to_add)
		if(domains_to_add.size > 0) then
			ef = OpenSSL::X509::ExtensionFactory.new
			ex = []
			ex << ef.create_extension("subjectAltName", domains_to_add.join(', '))
			request_extension_set = OpenSSL::ASN1::Set([OpenSSL::ASN1::Sequence(ex)])
			req.add_attribute(OpenSSL::X509::Attribute.new("extReq", request_extension_set))
			@san_names = domains_to_add
		end
	end
end
