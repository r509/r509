require 'spec_helper'

describe R509::Ca do
    before :each do
        @cert = TestFixtures::CERT
        @csr = TestFixtures::CSR
        @csr_invalid_signature = TestFixtures::CSR_INVALID_SIGNATURE
        @csr3 = TestFixtures::CSR3
        @test_ca_config = TestFixtures.test_ca_config
        @ca = R509::Ca.new(@test_ca_config)
    end

    it "properly issues server cert" do
        csr = R509::Csr.new
        csr.create_with_cert @cert,1024
        cert = @ca.sign_cert(csr,'server')
        cert.to_pem.should match(/BEGIN CERTIFICATE/)
        cert.subject.to_s.should == '/C=US/ST=Illinois/L=Chicago/O=Paul Kehrer/CN=langui.sh'
        extended_key_usage = cert.extensions['extendedKeyUsage']
        extended_key_usage[0]['value'].should == 'TLS Web Server Authentication'
    end
    it "issues with specified san domains" do
        csr = R509::Csr.new
        csr.create_with_cert @cert,1024
        cert = @ca.sign_cert(csr,'server',nil,['langui.sh','domain2.com'])
        cert.san_names.should == ['langui.sh','domain2.com']
    end
    it "issues with san domains from csr" do
        csr = R509::Csr.new @csr
        cert = @ca.sign_cert(csr,'server')
        cert.san_names.should == ['test.local','additionaldomains.com','saniam.com']
    end
    it "issues a csr made via array" do
        csr = R509::Csr.new
        csr.create_with_subject [['CN','langui.sh']],1024
        cert = @ca.sign_cert(csr,'server')
        cert.subject.to_s.should == '/CN=langui.sh'
    end
    it "issues a cert with the subject array provided" do
        csr = R509::Csr.new
        csr.create_with_subject [['CN','langui.sh']],1024
        cert = @ca.sign_cert(csr,'server',[['CN','someotherdomain.com']])
        cert.subject.to_s.should == '/CN=someotherdomain.com'
    end
    it "tests that policy identifiers are properly encoded" do
        csr = R509::Csr.new
        csr.create_with_subject [['CN','somedomain.com']],1024
        cert = @ca.sign_cert(csr,'server')
        cert.extensions['certificatePolicies'][0]['value'].should == "Policy: 2.16.840.1.12345.1.2.3.4.1\n  CPS: http://example.com/cps\n"
    end
    it "tests basic constraints CA:TRUE and pathlen:0 on a subroot" do
        csr = R509::Csr.new
        csr.create_with_subject [['CN','Subroot Test']],1024
        cert = @ca.sign_cert(csr,'subroot')
        cert.extensions['basicConstraints'][0]['value'].should == 'CA:TRUE, pathlen:0'
    end
    it "issues with md5" do
        csr = R509::Csr.new @csr3
        @ca.message_digest = 'md5'
        cert = @ca.sign_cert(csr,'server')
        cert.cert.signature_algorithm.should == 'md5WithRSAEncryption'
    end
    it "issues with sha1" do
        csr = R509::Csr.new @csr3
        @ca.message_digest = 'sha1'
        cert = @ca.sign_cert(csr,'server')
        cert.cert.signature_algorithm.should == 'sha1WithRSAEncryption'
    end
    it "issues with sha256" do
        csr = R509::Csr.new @csr3
        @ca.message_digest = 'sha256'
        cert = @ca.sign_cert(csr,'server')
        cert.cert.signature_algorithm.should == 'sha256WithRSAEncryption'
    end
    it "issues with sha512" do
        csr = R509::Csr.new @csr3
        @ca.message_digest = 'sha512'
        cert = @ca.sign_cert(csr,'server')
        cert.cert.signature_algorithm.should == 'sha512WithRSAEncryption'
    end
    it "issues with invalid hash (sha1 fallback)" do
        csr = R509::Csr.new @csr3
        @ca.message_digest = 'invalid'
        cert = @ca.sign_cert(csr,'server')
        cert.cert.signature_algorithm.should == 'sha1WithRSAEncryption'
    end
    it "raises exception unless you provide a proper config" do
        expect { R509::Ca.new('invalid') }.to raise_error(R509::R509Error)
    end
    it "raises exception when providing invalid ca profile" do
        csr = R509::Csr.new @csr
        expect { @ca.sign_cert(csr,'invalid') }.to raise_error(R509::R509Error)
    end
    it "raises exception when attempting to issue CSR with invalid signature" do
        csr = R509::Csr.new @csr_invalid_signature
        expect { @ca.sign_cert(csr,'server') }.to raise_error(R509::R509Error)
    end
end
