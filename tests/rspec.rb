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
		it "encodes the subject data from the cert"
			#csr = Csr.new
			#csr.create_csr_from_cert @@cert
			#csr.subject.should == [["C", "US", 19], ["ST", "Illinois", 19], ["L", "Chicago", 19], ["O", "Paul Kehrer", 19], ["CN", "langui.sh", 19]]
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
			csr.san_names.should == ["DNS: langui.sh", "DNS: victoly.com", "DNS: domain.local"]
		end
	end
end


describe Ca do
	context "issuing" do
		it "matches subject (non-san) (incomplete)" do
			csr = Csr.new
			csr.create_csr_from_cert @@cert
			cert = Ca::sign_cert(csr).to_pem
			cert.should match(/BEGIN CERTIFICATE/)
		end
		it "contains all san domains (incomplete)" do
			csr = Csr.new
			csr.create_csr_from_cert @@cert
			cert = Ca::sign_cert(csr,['langui.sh','domain2.com'])
			cert.san_names.should == ['langui.sh','domain2.com']
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
	context "generically" do
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
