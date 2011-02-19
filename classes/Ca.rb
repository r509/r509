require 'openssl'
require 'yaml'
$:.unshift File.expand_path("../../classes", __FILE__)
require 'Cert'

class Ca
	def self.sign_cert(pem,domains=[])
		@config = YAML::load(File.read("config.yaml"))
		req = OpenSSL::X509::Request.new pem
		san_names = merge_san_domains(req,domains)

		#load ca key and cert
		ca = OpenSSL::X509::Certificate.new File.read(@config['ca_cert'])
		ca_key = OpenSSL::PKey::RSA.new File.read(@config['ca_key'])

		#generate random serial in accordance with best practices
		serial = OpenSSL::BN.rand(160,0) # 160 bits is 20 bytes (octets). since second param is 0 the most significant bit must always be 1

		cert = OpenSSL::X509::Certificate.new
		#not_before will be set to 6 hours before now to prevent issues with bad system clocks (clients don't sync)
		from = Time.now - 6 * 60 * 60
		cert.subject = req.subject
		cert.issuer = ca.subject
		cert.not_before = from
		cert.not_after = from + 365 * 24 * 60 * 60
		cert.public_key = req.public_key
		cert.serial =serial
		cert.version = 2 # X509v3


		basic_constraint = "CA:FALSE"
		key_usage = ["digitalSignature","keyEncipherment"]
		ext_key_usage = ["serverAuth"]

		ef = OpenSSL::X509::ExtensionFactory.new
		ef.subject_certificate = cert
		ef.issuer_certificate = ca
		ex = []
		ex << ef.create_extension("basicConstraints", basic_constraint, true)
		ex << ef.create_extension("subjectKeyIdentifier", "hash")
		ex << ef.create_extension("keyUsage", key_usage.join(","))
		ex << ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always")
		ex << ef.create_extension("extendedKeyUsage", ext_key_usage.join(","))
		if ! san_names.empty? then
			ex << ef.create_extension("subjectAltName", san_names.join(",")) 
		end

		ex << ef.create_extension("crlDistributionPoints", @config['cdp_location'])

		if @config['ocsp_location'] then
		ex << ef.create_extension("authorityInfoAccess",
					"OCSP;" << @config['ocsp_location'])
		end
		cert.extensions = ex
		cert.sign ca_key, OpenSSL::Digest::SHA1.new
		Cert.new cert
	end

	private
	def self.merge_san_domains(req,domains)
		domains_from_csr = []
		#some prelim code to try to parse a SAN CSR
		#set = OpenSSL::ASN1.decode(req.attributes[0].value) #assuming just one attribute from above, that'd be extReq
		#seq = set.value[0]
		#seq.value[0].value.each{ |san|
		#	puts san.value.to_a
		#}
		if (domains.kind_of?(Array)) then
			parsed_domains = []
			domains.each { |domain| 
				parsed_domains.push('DNS: '+domain)
			}
			domains_from_csr.concat(parsed_domains).uniq!
		end
		domains_from_csr
	end
end
