require 'openssl'

class Cert
	attr_reader :cert, :san_names, :subject
	def initialize(cert)
		@subject = nil
		@san_names = nil
		begin
			@cert = OpenSSL::X509::Certificate.new cert
			@cert.extensions.to_a.each { |extension| 
				if (extension.to_a[0] == 'subjectAltName') then
					parse_san_extension(extension)
				end
			}
			@subject = @cert.subject
		#rescue OpenSSL::X509::CertificateError
		#	@cert = nil
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