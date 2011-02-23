require 'openssl'

module Ruby509
	class Csr
		attr_reader :san_names, :key, :subject, :req
		def initialize(*args)
			case args.size
				when 0
					@req = nil
					@subject = nil
					@san_names = nil
					@key = nil
				when 1
					@req = OpenSSL::X509::Request.new args[0]
					@subject = @req.subject
					@san_names = parse_domains_from_csr
					@key = nil
				when 2
					#this is mostly a dupe of above. either wrap in a method or find a better solution than case
					@req = OpenSSL::X509::Request.new args[0]
					@subject = @req.subject
					@san_names = parse_domains_from_csr
					@key = OpenSSL::PKey::RSA.new args[1]
					#verify on the OpenSSL::X509::Request object verifies public key match
					if !@req.verify(@key.public_key) then
						raise ArgumentError, 'Key does not match request.'
					end
				else
					raise ArgumentError, 'Too many arguments.'
			end
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

		def write_pem(filename)
			File.open(filename, 'w') {|f| f.write(@req.to_pem) }
		end

		def write_der(filename)
			File.open(filename, 'w') {|f| f.write(@req.to_der) }
		end

		def bit_strength
			if !@req.nil?
				#cast to int, convert to binary, count size
				@req.public_key.n.to_i.to_s(2).size
			end
		end

		#string pem
		#int bit_strength
		#array domains
		def create_with_cert(pem,bit_strength=2048,domains=[])
			domains_to_add = []
			san_extension = nil
			cert = OpenSSL::X509::Certificate.new(pem)
			cert.extensions.to_a.each { |extension| 
				if (extension.to_a[0] == 'subjectAltName') then
					domains_to_add = parse_san_extension(extension)
				end
			}
			if (domains.kind_of?(Array)) then
				parsed_domains = prefix_domains(domains)
				domains_to_add.concat(parsed_domains).uniq!
			end
			#name = OpenSSL::X509::Name.new(cert.subject.to_a) #this creates a new name object using an array
			create_csr(cert.subject,bit_strength,domains_to_add)
			@req.to_pem
		end

		#subject is array of form. you can also use oids (eg, '1.3.6.1.4.1.311.60.2.1.3')
		#[['CN','langui.sh'],['ST','Illinois'],['L','Chicago'],['C','US'],['emailAddress','ca@langui.sh']]
		def create_with_subject(subject,bit_strength=2048,domains=[])
			subject = OpenSSL::X509::Name.new subject
			parsed_domains = prefix_domains(domains)
			create_csr(subject,bit_strength,parsed_domains)
			@req.to_pem
		end

		private

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

		def parse_domains_from_csr
			domains_from_csr = []
			begin
				set = OpenSSL::ASN1.decode(@req.attributes[0].value) #assuming just one attribute from above, that'd be extReq. this may be unsafe
				seq = set.value[0]
				extensions = seq.value.collect{|asn1ext| OpenSSL::X509::Extension.new(asn1ext).to_a }
				extensions.each { |ext|
					if ext[0] == 'subjectAltName' then 
						domains_from_csr = ext[1].gsub(/DNS:/,'').split(',') 
						domains_from_csr = domains_from_csr.collect {|x| x.strip }
					end
				}
			rescue
			end
			domains_from_csr
		end
	end
end
