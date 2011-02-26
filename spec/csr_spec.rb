$:.unshift File.expand_path("../../lib", __FILE__)
$:.unshift File.expand_path("../", __FILE__)
require 'r509.rb'
require 'test_vars.rb'
require 'rspec'


describe R509::Csr do
	it "writes to pem" do
		csr = R509::Csr.new(@@csr)
		csr.write_pem('/tmp/csr')
		File.read('/tmp/csr').should == @@csr
		File.delete('/tmp/csr')
	end
	it "writes to der" do
		csr = R509::Csr.new(@@csr)
		csr.write_der('/tmp/csr')
		File.read('/tmp/csr').should == @@csr_der
		File.delete('/tmp/csr')
	end
	context "when initialized" do
		it "returns nil on to_pem" do
			csr = R509::Csr.new
			csr.to_pem.should == nil
		end
		it "returns nil on to_der" do
			csr = R509::Csr.new
			csr.to_der.should == nil
		end
		it "returns nil on to_s" do
			csr = R509::Csr.new
			csr.to_s.should == nil
		end
		it "raises exception when providing invalid csr" do
			expect { R509::Csr.new('invalid csr') }.to raise_error(OpenSSL::X509::RequestError)
		end
		it "raises exception when providing invalid key" do
			expect { R509::Csr.new(@@csr,'invalid key') }.to raise_error(OpenSSL::PKey::RSAError)
		end
		it "raises exception with too many params" do
			expect { R509::Csr.new(@@csr3,@@key3,'thirdparam') }.to raise_error(ArgumentError)
		end
	end
	context "when passing a cert (single param) to create_with_cert" do
		it "returns a valid pem" do
			csr = R509::Csr.new
			csr.create_with_cert @@cert
			csr.to_pem.should match(/CERTIFICATE REQUEST/)
		end
		it "has a public key length of 2048" do
			csr = R509::Csr.new
			csr.create_with_cert @@cert
			csr.bit_strength.should == 2048
		end
		it "encodes the subject data from the cert" do
			csr = R509::Csr.new
			csr.create_with_cert @@cert
			csr.subject.to_s.should == '/C=US/ST=Illinois/L=Chicago/O=Paul Kehrer/CN=langui.sh'
		end
		it "san domains from the cert should be encoded in the request" do
			csr = R509::Csr.new
			csr.create_with_cert @@cert_san
			csr.san_names.should == ['langui.sh']
		end
	end
	context "when passing a 1024 key length to create_with_cert" do
		it "has a public key length of 1024" do
			csr = R509::Csr.new
			csr.create_with_cert @@cert,1024
			csr.bit_strength.should == 1024
		end
	end
	context "when passing a list of domains to create_with_cert" do
		it "duplicates should be removed" do
			csr = R509::Csr.new
			csr.create_with_cert @@cert, 2048, ['langui.sh','victoly.com','victoly.com','domain.local','victoly.com']
			csr.san_names.should == ["langui.sh", "victoly.com", "domain.local"]
		end
	end
	context "when passing an array to create_with_subject" do
		it "generates a matching csr" do
			csr = R509::Csr.new
			csr.create_with_subject [['CN','langui.sh'],['ST','Illinois'],['L','Chicago'],['C','US'],['emailAddress','ca@langui.sh']]
			csr.subject.to_s.should == '/CN=langui.sh/ST=Illinois/L=Chicago/C=US/emailAddress=ca@langui.sh'
		end
		it "generates a matching csr with san domains" do
			csr = R509::Csr.new
			csr.create_with_subject [['CN','langui.sh'],['emailAddress','ca@langui.sh']],2048,['domain2.com','domain3.com']
			csr.subject.to_s.should == '/CN=langui.sh/emailAddress=ca@langui.sh'
			csr.san_names.should == ["domain2.com", "domain3.com"]
		end
		it "generates a matching csr when supplying raw oids" do
			csr = R509::Csr.new
			csr.create_with_subject [['2.5.4.3','common name'],['2.5.4.15','business category'],['2.5.4.7','locality'],['1.3.6.1.4.1.311.60.2.1.3','jurisdiction oid openssl typically does not know']]
			csr.subject.to_s.should == '/CN=common name/2.5.4.15=business category/L=locality/1.3.6.1.4.1.311.60.2.1.3=jurisdiction oid openssl typically does not know'
		end
	end
	context "when supplying an existing csr" do
		it "populates the bit_strength" do
			csr = R509::Csr.new @@csr
			csr.bit_strength.should == 2048
		end
		it "populates the subject" do
			csr = R509::Csr.new @@csr
			csr.subject.to_s.should == '/CN=test.local/O=Testing CSR'
		end
		it "parses the san names" do
			csr = R509::Csr.new @@csr
			csr.san_names.should == ["test.local", "additionaldomains.com", "saniam.com"]
		end
		it "parses san names when there are multiple non-SAN attributes" do
			csr = R509::Csr.new @@csr4_multiple_attrs
			csr.san_names.should == ["adomain.com", "anotherdomain.com", "justanexample.com"] 
		end
	end
	context "when supplying a key with csr" do
		it "raises exception on non-matching key" do
			expect { R509::Csr.new(@@csr,@@key_csr2) }.to raise_error(R509::R509Error)
		end
		it "accepts matching key" do
			csr = R509::Csr.new(@@csr2,@@key_csr2)
			csr.to_pem.should == @@csr2
		end
	end
end
