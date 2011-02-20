$:.unshift File.expand_path("../../classes", __FILE__)
$:.unshift File.expand_path("../", __FILE__)
require 'Csr'
require 'Ca'
require 'Cert'
require 'test_vars'


describe Csr do
	context "when initialized" do
		it "returns nil on to_pem" do
			csr = Csr.new
			csr.to_pem.should == nil
		end
		it "returns nil on to_der" do
			csr = Csr.new
			csr.to_der.should == nil
		end
		it "returns nil on to_s" do
			csr = Csr.new
			csr.to_s.should == nil
		end
	end
	context "when passing a cert (single param) to create_csr_from_cert" do
		it "returns a valid pem" do
			csr = Csr.new
			csr.create_csr_from_cert @@cert
			csr.to_pem.should match(/CERTIFICATE REQUEST/)
		end
		it "has a public key length of 2048" do
			csr = Csr.new
			csr.create_csr_from_cert @@cert
			csr.bit_strength.should == 2048
		end
		it "encodes the subject data from the cert" do
			csr = Csr.new
			csr.create_csr_from_cert @@cert
			csr.subject.to_s.should == '/C=US/ST=Illinois/L=Chicago/O=Paul Kehrer/CN=langui.sh'
		end
	end
	context "when passing a 1024 key length to create_csr_from_cert" do
		it "has a public key length of 1024" do
			csr = Csr.new
			csr.create_csr_from_cert @@cert,1024
			csr.bit_strength.should == 1024
		end
	end
	context "when passing a list of domains to create_csr_from_cert" do
		it "duplicates should be removed" do
			csr = Csr.new
			csr.create_csr_from_cert @@cert, 2048, ['langui.sh','victoly.com','victoly.com','domain.local','victoly.com']
			csr.san_names.should == ["langui.sh", "victoly.com", "domain.local"]
		end
	end
	context "when passing an array to create_csr_with_subject" do
		it "generates a matching csr" do
			csr = Csr.new
			csr.create_csr_with_subject [['CN','langui.sh'],['ST','Illinois'],['L','Chicago'],['C','US'],['emailAddress','ca@langui.sh']]
			csr.subject.to_s.should == '/CN=langui.sh/ST=Illinois/L=Chicago/C=US/emailAddress=ca@langui.sh'
		end
		it "generates a matching csr with san domains" do
			csr = Csr.new
			csr.create_csr_with_subject [['CN','langui.sh'],['emailAddress','ca@langui.sh']],2048,['domain2.com','domain3.com']
			csr.subject.to_s.should == '/CN=langui.sh/emailAddress=ca@langui.sh'
			csr.san_names.should == ["domain2.com", "domain3.com"]
		end
		it "generates a matching csr when supplying raw oids" do
			csr = Csr.new
			csr.create_csr_with_subject [['2.5.4.3','common name'],['2.5.4.15','business category'],['2.5.4.7','locality'],['1.3.6.1.4.1.311.60.2.1.3','jurisdiction oid openssl typically does not know']]
			csr.subject.to_s.should == '/CN=common name/2.5.4.15=business category/L=locality/1.3.6.1.4.1.311.60.2.1.3=jurisdiction oid openssl typically does not know'
		end
	end
end


describe Ca do
	context "issuing" do
		it "properly issues (non-san) server cert from test_ca" do
			csr = Csr.new
			csr.create_csr_from_cert @@cert
			cert = Ca::sign_cert(csr,'test_ca','server')
			cert.to_pem.should match(/BEGIN CERTIFICATE/)
			cert.subject.to_s.should == '/C=US/ST=Illinois/L=Chicago/O=Paul Kehrer/CN=langui.sh'
			extended_key_usage = cert.extensions['extendedKeyUsage']
			extended_key_usage[0]['value'].should == 'TLS Web Server Authentication'
		end
		it "contains all san domains (incomplete)" do
			csr = Csr.new
			csr.create_csr_from_cert @@cert
			cert = Ca::sign_cert(csr,'test_ca','server',['langui.sh','domain2.com'])
			cert.san_names.should == ['langui.sh','domain2.com']
		end
		it "issues a csr made via array" do
			csr = Csr.new
			csr.create_csr_with_subject [['CN','langui.sh']]
			cert = Ca::sign_cert(csr,'test_ca','server')
			cert.subject.to_s.should == '/CN=langui.sh'
		end
	end
end

describe Cert do
	context "when initialized with an OpenSSL::X509::Certificate" do
		it "returns pem on to_pem" do
			test_cert = Cert.new @@cert
			cert = Cert.new test_cert
			cert.to_pem.should == @@cert
		end
		it "returns der on to_der" do
			test_cert = Cert.new @@cert
			cert = Cert.new test_cert
			cert.to_der.should == @@der
		end
		it "returns pem on to_s" do
			test_cert = Cert.new @@cert
			cert = Cert.new test_cert
			cert.to_s.should == @@cert
		end
	end
	context "when initialized with a pem" do
		it "returns pem on to_pem" do
			cert = Cert.new @@cert
			cert.to_pem.should == @@cert
		end
		it "returns der on to_der" do
			cert = Cert.new @@cert
			cert.to_der.should == @@der
		end
		it "returns pem on to_s" do
			cert = Cert.new @@cert
			cert.to_s.should == @@cert
		end
	end
	context "generic tests" do
		it "returns list of san_names when it is a san cert" do
			cert = Cert.new @@cert_san
			cert.san_names.should == ['langui.sh']
		end
		it "returns an empty list when it is not a san cert" do
			cert = Cert.new @@cert
			cert.san_names.should == nil
		end
	end
end
