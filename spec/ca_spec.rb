$:.unshift File.expand_path("../../lib", __FILE__)
$:.unshift File.expand_path("../", __FILE__)
require 'r509.rb'
require 'test_vars.rb'
require 'rspec'


describe R509::Ca do
	it "properly issues server cert" do
		csr = R509::Csr.new
		csr.create_with_cert @@cert
		ca = R509::Ca.new('test_ca')
		cert = ca.sign_cert(csr,'server')
		cert.to_pem.should match(/BEGIN CERTIFICATE/)
		cert.subject.to_s.should == '/C=US/ST=Illinois/L=Chicago/O=Paul Kehrer/CN=langui.sh'
		extended_key_usage = cert.extensions['extendedKeyUsage']
		extended_key_usage[0]['value'].should == 'TLS Web Server Authentication'
	end
	it "issues with specified san domains" do
		csr = R509::Csr.new
		csr.create_with_cert @@cert
		ca = R509::Ca.new 'test_ca'
		cert = ca.sign_cert(csr,'server',nil,['langui.sh','domain2.com'])
		cert.san_names.should == ['langui.sh','domain2.com']
	end
	it "issues with san domains from csr" do
		csr = R509::Csr.new @@csr
		ca = R509::Ca.new 'test_ca'
		cert = ca.sign_cert(csr,'server')
		cert.san_names.should == ['test.local','additionaldomains.com','saniam.com']
	end
	it "issues a csr made via array" do
		csr = R509::Csr.new
		csr.create_with_subject [['CN','langui.sh']]
		ca = R509::Ca.new 'test_ca'
		cert = ca.sign_cert(csr,'server')
		cert.subject.to_s.should == '/CN=langui.sh'
	end
	it "issues a cert with the subject array provided" do
		csr = R509::Csr.new
		csr.create_with_subject [['CN','langui.sh']]
		ca = R509::Ca.new 'test_ca'
		cert = ca.sign_cert(csr,'server',[['CN','someotherdomain.com']])
		cert.subject.to_s.should == '/CN=someotherdomain.com'
	end
	it "tests that policy identifiers are properly encoded" do
		csr = R509::Csr.new
		csr.create_with_subject [['CN','somedomain.com']]
		ca = R509::Ca.new 'test_ca'
		cert = ca.sign_cert(csr,'server')
		cert.extensions['certificatePolicies'][0]['value'].should == "Policy: 2.16.840.1.9999999999.1.2.3.4.1\n  CPS: http://example.com/cps\n"
	end
	it "tests basic constraints CA:TRUE and pathlen:0 on a subroot" do
		csr = R509::Csr.new
		csr.create_with_subject [['CN','Subroot Test']]
		ca = R509::Ca.new 'test_ca'
		cert = ca.sign_cert(csr,'subroot')
		cert.extensions['basicConstraints'][0]['value'].should == 'CA:TRUE, pathlen:0'
	end
	it "issues with md5" do
		csr = R509::Csr.new @@csr3
		ca = R509::Ca.new 'test_ca'
		ca.message_digest = 'md5'
		cert = ca.sign_cert(csr,'server')
		cert.cert.signature_algorithm.should == 'md5WithRSAEncryption'
	end
	it "issues with sha1" do
		csr = R509::Csr.new @@csr3
		ca = R509::Ca.new 'test_ca'
		ca.message_digest = 'sha1'
		cert = ca.sign_cert(csr,'server')
		cert.cert.signature_algorithm.should == 'sha1WithRSAEncryption'
	end
	it "issues with sha256" do
		csr = R509::Csr.new @@csr3
		ca = R509::Ca.new 'test_ca'
		ca.message_digest = 'sha256'
		cert = ca.sign_cert(csr,'server')
		cert.cert.signature_algorithm.should == 'sha256WithRSAEncryption'
	end
	it "issues with sha512" do
		csr = R509::Csr.new @@csr3
		ca = R509::Ca.new 'test_ca'
		ca.message_digest = 'sha512'
		cert = ca.sign_cert(csr,'server')
		cert.cert.signature_algorithm.should == 'sha512WithRSAEncryption'
	end
	it "issues with invalid hash (sha1 fallback)" do
		csr = R509::Csr.new @@csr3
		ca = R509::Ca.new 'test_ca'
		ca.message_digest = 'invalid'
		cert = ca.sign_cert(csr,'server')
		cert.cert.signature_algorithm.should == 'sha1WithRSAEncryption'
	end
end
