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
        csr = R509::Csr.new(:cert => @cert, :bit_strength => 1024)
        cert = @ca.sign_cert({ :csr => csr, :profile_name => 'server' })
        cert.to_pem.should match(/BEGIN CERTIFICATE/)
        cert.subject.to_s.should == '/C=US/ST=Illinois/L=Chicago/O=Paul Kehrer/CN=langui.sh'
        extended_key_usage = cert.extensions['extendedKeyUsage']
        extended_key_usage[0]['value'].should == 'TLS Web Server Authentication'
    end
    it "issues with specified san domains" do
        csr = R509::Csr.new(:cert => @cert, :bit_strength => 1024)
        cert = @ca.sign_cert(:csr => csr, :profile_name => 'server', :domains => ['langui.sh','domain2.com'])
        cert.san_names.should == ['langui.sh','domain2.com']
    end
    it "issues with san domains from csr" do
        csr = R509::Csr.new(:csr => @csr)
        cert = @ca.sign_cert(:csr => csr, :profile_name => 'server')
        cert.san_names.should == ['test.local','additionaldomains.com','saniam.com']
    end
    it "issues a csr made via array" do
        csr = R509::Csr.new(:subject => [['CN','langui.sh']], :bit_strength => 1024)
        cert = @ca.sign_cert(:csr => csr, :profile_name => 'server')
        cert.subject.to_s.should == '/CN=langui.sh'
    end
    it "issues a cert with the subject array provided" do
        csr = R509::Csr.new(:csr => @csr)
        cert = @ca.sign_cert(:csr => csr, :profile_name => 'server', :subject => [['CN','someotherdomain.com']])
        cert.subject.to_s.should == '/CN=someotherdomain.com'
    end
    it "tests that policy identifiers are properly encoded" do
        csr = R509::Csr.new(:csr => @csr)
        cert = @ca.sign_cert(:csr => csr, :profile_name => 'server')
        cert.extensions['certificatePolicies'][0]['value'].should == "Policy: 2.16.840.1.12345.1.2.3.4.1\n  CPS: http://example.com/cps\n"
    end
    it "tests basic constraints CA:TRUE and pathlen:0 on a subroot" do
        csr = R509::Csr.new(:csr => @csr)
        cert = @ca.sign_cert(:csr => csr, :profile_name => 'subroot')
        cert.extensions['basicConstraints'][0]['value'].should == 'CA:TRUE, pathlen:0'
    end
    it "issues with md5" do
        csr = R509::Csr.new(:csr => @csr3)
        cert = @ca.sign_cert(:csr => csr, :profile_name => 'server', :message_digest => 'md5')
        cert.cert.signature_algorithm.should == 'md5WithRSAEncryption'
    end
    it "issues with sha1" do
        csr = R509::Csr.new(:csr => @csr3)
        cert = @ca.sign_cert(:csr => csr, :profile_name => 'server', :message_digest => 'sha1')
        cert.cert.signature_algorithm.should == 'sha1WithRSAEncryption'
    end
    it "issues with sha256" do
        csr = R509::Csr.new(:csr => @csr3)
        cert = @ca.sign_cert(:csr => csr, :profile_name => 'server', :message_digest => 'sha256')
        cert.cert.signature_algorithm.should == 'sha256WithRSAEncryption'
    end
    it "issues with sha512" do
        csr = R509::Csr.new(:csr => @csr3)
        cert = @ca.sign_cert(:csr => csr, :profile_name => 'server', :message_digest => 'sha512')
        cert.cert.signature_algorithm.should == 'sha512WithRSAEncryption'
    end
    it "issues with invalid hash (sha1 fallback)" do
        csr = R509::Csr.new(:csr => @csr3)
        cert = @ca.sign_cert(:csr => csr, :profile_name => 'server', :message_digest => 'invalid')
        cert.cert.signature_algorithm.should == 'sha1WithRSAEncryption'
    end
    it "generates random serial when serial is not specified" do
        csr = R509::Csr.new(:csr => @csr3)
        cert = @ca.sign_cert(:csr => csr, :profile_name => "server")
        cert.cert.serial.to_s.size.should >= 48
    end
    it "accepts specified serial number" do
        csr = R509::Csr.new(:csr => @csr3)
        cert = @ca.sign_cert(:csr => csr, :profile_name => "server", :serial => 12345)
        cert.cert.serial.should == 12345
    end
    it "has default notBefore/notAfter dates" do
        not_before = (Time.now - (6 * 60 * 60)).utc
        not_after = (Time.now - (6 * 60 * 60) + (365 * 24 * 60 * 60)).utc
        csr = R509::Csr.new(:csr => @csr3)
        cert = @ca.sign_cert(:csr => csr, :profile_name => "server")
        cert.cert.not_before.year.should == not_before.year
        cert.cert.not_before.month.should == not_before.month
        cert.cert.not_before.day.should == not_before.day
        cert.cert.not_before.hour.should == not_before.hour
        cert.cert.not_before.min.should == not_before.min
        cert.cert.not_after.year.should == not_after.year
        cert.cert.not_after.month.should == not_after.month
        cert.cert.not_after.day.should == not_after.day
        cert.cert.not_after.hour.should == not_after.hour
        cert.cert.not_after.min.should == not_after.min
    end
    it "allows you to specify notBefore/notAfter dates" do
        not_before = Time.now - 5 * 60 * 60
        not_after = Time.now + 5 * 60 * 60
        csr = R509::Csr.new(:csr => @csr3)
        cert = @ca.sign_cert(:csr => csr, :profile_name => "server", :not_before => not_before, :not_after => not_after)
        cert.cert.not_before.ctime.should == not_before.utc.ctime
        cert.cert.not_after.ctime.should == not_after.utc.ctime
    end
    it "raises exception unless you provide a proper config" do
        expect { R509::Ca.new('invalid') }.to raise_error(R509::R509Error)
    end
    it "raises exception when providing invalid ca profile" do
        csr = R509::Csr.new(:csr => @csr)
        expect { @ca.sign_cert(:csr => csr, :profile_name => 'invalid') }.to raise_error(R509::R509Error)
    end
    it "raises exception when attempting to issue CSR with invalid signature" do
        csr = R509::Csr.new(:csr => @csr_invalid_signature)
        expect { @ca.sign_cert(:csr => csr, :profile_name => 'server') }.to raise_error(R509::R509Error, 'Certificate request signature is invalid.')
    end
end
