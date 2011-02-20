require 'openssl'
require 'yaml'
$:.unshift File.expand_path("../../classes", __FILE__)
require 'Cert'

class Ca
	def self.sign_cert(pem,ca,profile,domains=[])
		@config = YAML::load(File.read("config.yaml"))
		req = OpenSSL::X509::Request.new pem
		san_names = merge_san_domains(req,domains)

		#load ca key and cert
		ca_cert = OpenSSL::X509::Certificate.new File.read(@config[ca]['ca_cert'])
		ca_key = OpenSSL::PKey::RSA.new File.read(@config[ca]['ca_key'])

		#generate random serial in accordance with best practices
		serial = OpenSSL::BN.rand(160,0) # 160 bits is 20 bytes (octets). since second param is 0 the most significant bit must always be 1

		cert = OpenSSL::X509::Certificate.new
		#not_before will be set to 6 hours before now to prevent issues with bad system clocks (clients don't sync)
		from = Time.now - 6 * 60 * 60
		cert.subject = req.subject
		cert.issuer = ca_cert.subject
		cert.not_before = from
		cert.not_after = from + 365 * 24 * 60 * 60
		cert.public_key = req.public_key
		cert.serial =serial
		cert.version = 2 # X509v3


		basic_constraints = @config[ca][profile]['basic_constraints']
		key_usage = @config[ca][profile]['key_usage']
		extended_key_usage = @config[ca][profile]['extended_key_usage']

		ef = OpenSSL::X509::ExtensionFactory.new
		ef.subject_certificate = cert
		ef.issuer_certificate = ca_cert
		ext = []
		ext << ef.create_extension("basicConstraints", basic_constraints, true)
		ext << ef.create_extension("subjectKeyIdentifier", "hash")
		ext << ef.create_extension("keyUsage", key_usage.join(","))
		ext << ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always")
		ext << ef.create_extension("extendedKeyUsage", extended_key_usage.join(","))
		if ! san_names.empty? then
			ext << ef.create_extension("subjectAltName", san_names.join(",")) 
		end

		ext << ef.create_extension("crlDistributionPoints", @config[ca]['cdp_location'])

		if @config[ca]['ocsp_location'] then
		ext << ef.create_extension("authorityInfoAccess",
					"OCSP;" << @config[ca]['ocsp_location'])
		end
		cert.extensions = ext
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
