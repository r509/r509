require 'openssl'

class Cert
	attr_reader :cert, :san_names, :subject, :key
	def initialize(*args)
		@subject = nil
		@san_names = nil
		@extensions = nil
		@cert = nil
		@key = nil
		case args.size
			when 0 then raise ArgumentError, 'Too few args. 1-2 (cert,key)'
			when 1
				@cert = OpenSSL::X509::Certificate.new args[0]
				@cert.extensions.to_a.each { |extension| 
					if (extension.to_a[0] == 'subjectAltName') then
						parse_san_extension(extension)
					end
				}
				@subject = @cert.subject
			when 2
				#duplicated from case 1 just like with Csr...need better solution
				@cert = OpenSSL::X509::Certificate.new args[0]
				@cert.extensions.to_a.each { |extension| 
					if (extension.to_a[0] == 'subjectAltName') then
						parse_san_extension(extension)
					end
				}
				@subject = @cert.subject
				@key = OpenSSL::PKey::RSA.new args[1]
				#we can't use verify here because verify does not do what it does for CSR
				#looks like it tries to verify the chain
				if !(@cert.public_key.to_s == @key.public_key.to_s) then
					raise ArgumentError, 'Key does not match cert.'
				end
			else
				raise ArgumentError, 'Too many args. Max 2 (cert,key)'
		end
	end

	def to_pem
		if(@cert.kind_of?(OpenSSL::X509::Certificate)) then
			return @cert.to_pem.chomp
		end
	end

	alias :to_s :to_pem

	def to_der
		if(@cert.kind_of?(OpenSSL::X509::Certificate)) then
			return @cert.to_der
		end
	end

	def not_before
		@cert.not_before
	end

	def not_after
		@cert.not_after
	end

	def extensions
		parsed_extensions = Hash.new
		@cert.extensions.to_a.each { |extension| 
			extension = extension.to_a
			if(!parsed_extensions[extension[0]].kind_of?(Array)) then
				parsed_extensions[extension[0]] = []
			end
			hash = {'value' => extension[1], 'critical' => extension[2]}
			parsed_extensions[extension[0]].push hash
		}
		parsed_extensions
	end

	#takes OpenSSL::X509::Extension object
	def parse_san_extension(extension)
		san_string = extension.to_a[1]
		stripped = []
		san_string.split(',').each{ |name| 
			stripped.push name.gsub(/DNS:/,'').strip
		}
		@san_names = stripped
	end
end
