require 'openssl'
require 'yaml'
$:.unshift File.expand_path("../../classes", __FILE__)
require 'Cert'

class Ca
	def self.sign_cert(pem,ca,profile,subject=nil,domains=[])
		@config = YAML::load(File.read("config.yaml"))
		@req = OpenSSL::X509::Request.new pem
		san_names = merge_san_domains(domains)

		#load ca key and cert
		ca_cert = OpenSSL::X509::Certificate.new File.read(@config[ca]['ca_cert'])
		ca_key = OpenSSL::PKey::RSA.new File.read(@config[ca]['ca_key'])

		#generate random serial in accordance with best practices
		#guidelines state 20-bits of entropy, but we can cram more in
		#per rfc5280 conforming CAs can make the serial field up to 20 octets
		serial = OpenSSL::BN.rand(160,0) # 160 bits is 20 bytes (octets).
		#since second param is 0 the most significant bit must always be 1
		#this theoretically gives us 159 bits of entropy

		cert = OpenSSL::X509::Certificate.new
		#not_before will be set to 6 hours before now to prevent issues with bad system clocks (clients don't sync)
		from = Time.now - 6 * 60 * 60
		if(subject.kind_of?(Array)) then
			name = OpenSSL::X509::Name.new subject
			#the following line shouldn't be needed since Name can take an array. remove when i'm sure of this
			#subject.each do |item| name.add_entry(item[0],item[1]) end
			cert.subject = name
		else
			cert.subject = @req.subject
		end
		cert.issuer = ca_cert.subject
		cert.not_before = from
		cert.not_after = from + 365 * 24 * 60 * 60
		cert.public_key = @req.public_key
		cert.serial =serial
		cert.version = 2 #2 means v3


		basic_constraints = @config[ca][profile]['basic_constraints']
		key_usage = @config[ca][profile]['key_usage']
		extended_key_usage = @config[ca][profile]['extended_key_usage']
		certificate_policies = @config[ca][profile]['certificate_policies']
		ef = OpenSSL::X509::ExtensionFactory.new
		ef.subject_certificate = cert
		ef.issuer_certificate = ca_cert
		ext = []
		ext << ef.create_extension("basicConstraints", basic_constraints, true)
		ext << ef.create_extension("subjectKeyIdentifier", "hash")
		ext << ef.create_extension("keyUsage", key_usage.join(","))
		ext << ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always")
		if(extended_key_usage.size > 0) then
			ext << ef.create_extension("extendedKeyUsage", extended_key_usage.join(","))
		end
		conf = build_conf('certPolicies',@config[ca][profile]['certificate_policies'])
		ef.config = OpenSSL::Config.parse(conf)
		#ef.config = OpenSSL::Config.parse(<<-_end_of_cnf_)
		#[certPolicies]
		#CPS.1 = http://www.example.com/cps
		#_end_of_cnf_


		ext << ef.create_extension("certificatePolicies", '@certPolicies')
		if ! san_names.empty? then
			ext << ef.create_extension("subjectAltName", san_names.join(",")) 
		end

		ext << ef.create_extension("crlDistributionPoints", @config[ca]['cdp_location'])

		if @config[ca]['ocsp_location'] then
		ext << ef.create_extension("authorityInfoAccess",
					"OCSP;" << @config[ca]['ocsp_location'])
		end
		cert.extensions = ext
		message_digest = case @config[ca]['message_digest'].downcase
			when 'sha1' then OpenSSL::Digest::SHA1.new
			when 'sha256' then OpenSSL::Digest::SHA256.new
			when 'sha512' then OpenSSL::Digest::SHA512.new
			when 'md5' then OpenSSL::Digest::MD5.new
			else OpenSSL::Digest::SHA1.new
		end
		cert.sign ca_key, message_digest
		Cert.new cert
	end

	private
	def self.merge_san_domains(domains)
		domains_from_csr = parse_domains_from_csr
		if (domains.kind_of?(Array)) then
			parsed_domains = []
			domains.each { |domain| 
				parsed_domains.push('DNS: '+domain)
			}
			domains_from_csr.concat(parsed_domains).uniq!
		end
		domains_from_csr
	end

	#this code is identical to the method in Csr. think about moving these to a helper class
	def self.parse_domains_from_csr
		domains_from_csr = []
		begin
			set = OpenSSL::ASN1.decode(@req.attributes[0].value) #assuming just one attribute from above, that'd be extReq. this may be unsafe
			seq = set.value[0]
			extensions = seq.value.collect{|asn1ext| OpenSSL::X509::Extension.new(asn1ext).to_a }
			extensions.each { |ext| 
				domains_from_csr = ext[1].gsub(/DNS:/,'').split(',') 
				domains_from_csr = domains_from_csr.collect {|x| x.strip }
			}
		rescue
		end
		domains_from_csr
	end

	def self.build_conf(section,data)
		conf = ["[#{section}]"]
		conf.concat data
		conf.join "\n"
	end
end
