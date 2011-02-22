$:.unshift File.expand_path("../../lib", __FILE__)
$:.unshift File.expand_path("../", __FILE__)
require 'ruby509'
require 'test_vars'


describe Ruby509::Csr do
	context "when initialized" do
		it "returns nil on to_pem" do
			csr = Ruby509::Csr.new
			csr.to_pem.should == nil
		end
		it "returns nil on to_der" do
			csr = Ruby509::Csr.new
			csr.to_der.should == nil
		end
		it "returns nil on to_s" do
			csr = Ruby509::Csr.new
			csr.to_s.should == nil
		end
		it "raises exception when providing invalid csr" do
			expect { Ruby509::Csr.new('invalid csr') }.to raise_error(OpenSSL::X509::RequestError)
		end
		it "raises exception when providing invalid key" do
			expect { Ruby509::Csr.new(@@csr,'invalid key') }.to raise_error(OpenSSL::PKey::RSAError)
		end
			
	end
	context "when passing a cert (single param) to create_with_cert" do
		it "returns a valid pem" do
			csr = Ruby509::Csr.new
			csr.create_with_cert @@cert
			csr.to_pem.should match(/CERTIFICATE REQUEST/)
		end
		it "has a public key length of 2048" do
			csr = Ruby509::Csr.new
			csr.create_with_cert @@cert
			csr.bit_strength.should == 2048
		end
		it "encodes the subject data from the cert" do
			csr = Ruby509::Csr.new
			csr.create_with_cert @@cert
			csr.subject.to_s.should == '/C=US/ST=Illinois/L=Chicago/O=Paul Kehrer/CN=langui.sh'
		end
	end
	context "when passing a 1024 key length to create_with_cert" do
		it "has a public key length of 1024" do
			csr = Ruby509::Csr.new
			csr.create_with_cert @@cert,1024
			csr.bit_strength.should == 1024
		end
	end
	context "when passing a list of domains to create_with_cert" do
		it "duplicates should be removed" do
			csr = Ruby509::Csr.new
			csr.create_with_cert @@cert, 2048, ['langui.sh','victoly.com','victoly.com','domain.local','victoly.com']
			csr.san_names.should == ["langui.sh", "victoly.com", "domain.local"]
		end
	end
	context "when passing an array to create_with_subject" do
		it "generates a matching csr" do
			csr = Ruby509::Csr.new
			csr.create_with_subject [['CN','langui.sh'],['ST','Illinois'],['L','Chicago'],['C','US'],['emailAddress','ca@langui.sh']]
			csr.subject.to_s.should == '/CN=langui.sh/ST=Illinois/L=Chicago/C=US/emailAddress=ca@langui.sh'
		end
		it "generates a matching csr with san domains" do
			csr = Ruby509::Csr.new
			csr.create_with_subject [['CN','langui.sh'],['emailAddress','ca@langui.sh']],2048,['domain2.com','domain3.com']
			csr.subject.to_s.should == '/CN=langui.sh/emailAddress=ca@langui.sh'
			csr.san_names.should == ["domain2.com", "domain3.com"]
		end
		it "generates a matching csr when supplying raw oids" do
			csr = Ruby509::Csr.new
			csr.create_with_subject [['2.5.4.3','common name'],['2.5.4.15','business category'],['2.5.4.7','locality'],['1.3.6.1.4.1.311.60.2.1.3','jurisdiction oid openssl typically does not know']]
			csr.subject.to_s.should == '/CN=common name/2.5.4.15=business category/L=locality/1.3.6.1.4.1.311.60.2.1.3=jurisdiction oid openssl typically does not know'
		end
	end
	context "when supplying an existing csr" do
		it "populates the bit_strength" do
			csr = Ruby509::Csr.new @@csr
			csr.bit_strength.should == 2048
		end
		it "populates the subject" do
			csr = Ruby509::Csr.new @@csr
			csr.subject.to_s.should == '/CN=test.local/O=Testing CSR'
		end
		it "parses the san names" do
			csr = Ruby509::Csr.new @@csr
			csr.san_names.should == ["test.local", "additionaldomains.com", "saniam.com"]
		end
	end
	context "when supplying a key with csr" do
		it "raises exception on non-matching key" do
			expect { Ruby509::Csr.new(@@csr,@@key_csr2) }.to raise_error(ArgumentError)
		end
		it "accepts matching key" do
			csr = Ruby509::Csr.new(@@csr2,@@key_csr2)
			csr.to_pem.should == "-----BEGIN CERTIFICATE REQUEST-----\nMIICaTCCAVECAQAwJDEVMBMGA1UEAwwMbWF0Y2hpbmcuY29tMQswCQYDVQQGEwJV\nUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOWrrdjIluh8xAuvZoww\nbapzAcIWpyFUH6WjCi2W+eWqf+4BAA+xWJGvVrUeAmi5RF0wkVNIURUZia899M4e\nk/wN10Cimuweh9KBMAWECxaoHwDBQ16EaHqx7TYBsglOFqnusOBuznvl+CJLPNCz\ni+YW62WJVpoSPh1sTh46skGtZ1QtCNjGwp0rlmfVWehxeqBYLWTC8PtUYI52PjDn\n63ufY9IFjOI39s/7Van2l7ClpBgNMAM71iUcGRcS2q5n1h0yVUW/39Vrcn42p9FO\nbCgirq4QO8WcnsVKebI4xbgU8egJ/ljRnNy2Vmiy32grnJa5dL4VeVx2OpsBebjn\nP3UCAwEAAaAAMA0GCSqGSIb3DQEBBQUAA4IBAQANE6J7l7S2E8Ej+XTB9TpRkL6K\nnT2P9/UY42siYIyu3fHFE0/CrgO4QIkuGPTFRfxGp9OIAQOI271GvWn7FVTkI4v0\nk9hATXlFOqH0TKwbW2ukW65wTxDitXJlDBoiZfZ7blcCzzKA1VELryTpp2/gsqGq\nwqj8T87MXpEDL6vWlK3l0+ig8quUsFRCKA0BXH1eR318DoosbjE39QmTPLUfCrTW\nHYxKrL6+G9oY5o53+NSA/iQJHk8N/757GMeZA5LD03l5zn9DVnMZMKyGZIJaCYnL\npr4urCKvKaeLCEv+NxHq8mkF2ke9WHJKahTGSMJjAbM3Y+a9Q95TaHQXRoJ1\n-----END CERTIFICATE REQUEST-----\n"
		end
	end
end


describe Ruby509::Ca do
	it "properly issues (non-san) server cert from test_ca" do
		csr = Ruby509::Csr.new
		csr.create_with_cert @@cert
		ca = Ruby509::Ca.new('test_ca')
		cert = ca.sign_cert(csr,'server')
		cert.to_pem.should match(/BEGIN CERTIFICATE/)
		cert.subject.to_s.should == '/C=US/ST=Illinois/L=Chicago/O=Paul Kehrer/CN=langui.sh'
		extended_key_usage = cert.extensions['extendedKeyUsage']
		extended_key_usage[0]['value'].should == 'TLS Web Server Authentication'
	end
	it "contains all san domains (incomplete)" do
		csr = Ruby509::Csr.new
		csr.create_with_cert @@cert
		ca = Ruby509::Ca.new 'test_ca'
		cert = ca.sign_cert(csr,'server',nil,['langui.sh','domain2.com'])
		cert.san_names.should == ['langui.sh','domain2.com']
	end
	it "issues a csr made via array" do
		csr = Ruby509::Csr.new
		csr.create_with_subject [['CN','langui.sh']]
		ca = Ruby509::Ca.new 'test_ca'
		cert = ca.sign_cert(csr,'server')
		cert.subject.to_s.should == '/CN=langui.sh'
	end
	it "issues a cert with the subject array provided" do
		csr = Ruby509::Csr.new
		csr.create_with_subject [['CN','langui.sh']]
		ca = Ruby509::Ca.new 'test_ca'
		cert = ca.sign_cert(csr,'server',[['CN','someotherdomain.com']])
		cert.subject.to_s.should == '/CN=someotherdomain.com'
	end
	it "tests that policy identifiers are properly encoded" do
		csr = Ruby509::Csr.new
		csr.create_with_subject [['CN','somedomain.com']]
		ca = Ruby509::Ca.new 'test_ca'
		cert = ca.sign_cert(csr,'server')
		cert.extensions['certificatePolicies'][0]['value'].should == "Policy: 2.16.840.1.9999999999.1.2.3.4.1\n  CPS: http://example.com/cps\n"
	end
	it "tests basic constraints CA:TRUE and pathlen:0 on a subroot" do
		csr = Ruby509::Csr.new
		csr.create_with_subject [['CN','Subroot Test']]
		ca = Ruby509::Ca.new 'test_ca'
		cert = ca.sign_cert(csr,'subroot')
		cert.extensions['basicConstraints'][0]['value'].should == 'CA:TRUE, pathlen:0'
	end
end

describe Ruby509::Cert do
	it "returns list of san_names when it is a san cert" do
		cert = Ruby509::Cert.new @@cert_san
		cert.san_names.should == ['langui.sh']
	end
	it "returns an empty list when it is not a san cert" do
		cert = Ruby509::Cert.new @@cert
		cert.san_names.should == nil
	end
	it "raises exception when providing invalid cert" do
			expect { Ruby509::Cert.new('invalid cert') }.to raise_error(OpenSSL::X509::CertificateError)
	end
	it "raises exception when providing invalid key" do
			expect { Ruby509::Cert.new(@@cert,'invalid key') }.to raise_error(OpenSSL::PKey::RSAError)
	end
	it "raises exception on non-matching key" do
			expect { Ruby509::Cert.new(@@cert,@@key3) }.to raise_error(ArgumentError)
	end
	it "return normal object on matching key/cert pair" do
			expect { Ruby509::Cert.new(@@cert3,@@key3) }.to_not raise_error
	end
	context "when initialized with an OpenSSL::X509::Certificate" do
		it "returns pem on to_pem" do
			test_cert = Ruby509::Cert.new @@cert
			cert = Ruby509::Cert.new test_cert
			cert.to_pem.should == @@cert
		end
		it "returns der on to_der" do
			test_cert = Ruby509::Cert.new @@cert
			cert = Ruby509::Cert.new test_cert
			cert.to_der.should == @@der
		end
		it "returns pem on to_s" do
			test_cert = Ruby509::Cert.new @@cert
			cert = Ruby509::Cert.new test_cert
			cert.to_s.should == @@cert
		end
	end
	context "when initialized with a pem" do
		it "returns pem on to_pem" do
			cert = Ruby509::Cert.new @@cert
			cert.to_pem.should == @@cert
		end
		it "returns der on to_der" do
			cert = Ruby509::Cert.new @@cert
			cert.to_der.should == @@der
		end
		it "returns pem on to_s" do
			cert = Ruby509::Cert.new @@cert
			cert.to_s.should == @@cert
		end
	end
end

describe Ruby509::Crl do
	it "generates a crl from an existing revocation list" do
		crl = Ruby509::Crl.new('test_ca')
		crl.generate_crl.should match(/BEGIN X509 CRL/)
	end
	it "adds a cert to the revocation list" do
		crl = Ruby509::Crl.new('test_ca')
		crl.revoke_cert(383834832)
		crl.generate_crl.should match(/BEGIN X509 CRL/)
		found = false
		crl.revoked_list.each { |item| 
			if item['serial'] == 383834832 then
				found = true
			end	
		}
		found.should == true
	end
	it "removes a cert from the revocation list" do
		crl = Ruby509::Crl.new('test_ca')
		crl.unrevoke_cert(383834832)
		crl.generate_crl
		found = false
		crl.revoked_list.each { |item| 
			if item['serial'] == 383834832 then
				found = true
			end	
		}
		found.should == false
	end
	it "sets validity period properly through the setter" do
		crl = Ruby509::Crl.new('test_ca')
		crl.validity_hours = 2
		now = Time.at Time.now.to_i
		crl.generate_crl
		crl.next_update.should == (now+2*3600)
		
	end
end
