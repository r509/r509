require 'spec_helper'

describe R509::CertificateAuthority::Signer do
    before :each do
        @cert = TestFixtures::CERT
        @csr = TestFixtures::CSR
        @csr_invalid_signature = TestFixtures::CSR_INVALID_SIGNATURE
        @csr3 = TestFixtures::CSR3
        @test_ca_config = TestFixtures.test_ca_config
        @ca = R509::CertificateAuthority::Signer.new(@test_ca_config)
        @ca_no_profile = R509::CertificateAuthority::Signer.new(TestFixtures.test_ca_no_profile_config)
        @spki = TestFixtures::SPKI
    end

    it "raises an error if you don't pass csr or spki" do
        expect { @ca.sign({ :profile_name => 'server' }) }.to raise_error(ArgumentError, "You must supply either :csr or :spki")
    end
    it "raises an error if you pass a config that has no private key for ca_cert" do
        config = R509::Config::CaConfig.new( :ca_cert => R509::Cert.new( :cert => TestFixtures::TEST_CA_CERT) )
        profile = R509::Config::CaProfile.new
        config.set_profile("some_profile",profile)
        expect { R509::CertificateAuthority::Signer.new(config) }.to raise_error(R509::R509Error, "You must have a private key associated with your CA certificate to issue")
    end
    it "raises an error if you pass both csr and spki" do
        csr = R509::Csr.new(:csr => @csr)
        spki = R509::Spki.new(:spki => @spki, :subject=>[['CN','test']])
        expect { @ca.sign({ :spki => spki, :csr => csr, :profile_name => 'server' }) }.to raise_error(ArgumentError, "You can't pass both :csr and :spki")
    end
    it "raise an error if you don't pass an R509::Spki in :spki" do
        spki = OpenSSL::Netscape::SPKI.new(@spki)
        expect { @ca.sign({ :spki => spki, :profile_name => 'server' }) }.to raise_error(ArgumentError, 'You must pass an R509::Spki object for :spki')
    end
    it "raise an error if you don't pass an R509::Csr in :csr" do
        csr = OpenSSL::X509::Request.new(@csr)
        expect { @ca.sign({ :csr => csr, :profile_name => 'server' }) }.to raise_error(ArgumentError, 'You must pass an R509::Csr object for :csr')
    end
    it "raises an error if you have no CaProfiles with your CaConfig when attempting to issue a cert" do
        config = R509::Config::CaConfig.new(
            :ca_cert => TestFixtures.test_ca_cert
        )
        ca = R509::CertificateAuthority::Signer.new(config)
        expect { ca.sign(:csr => @csr)  }.to raise_error(R509::R509Error, 'You must have at least one CaProfile on your CaConfig to issue')
    end
    it "properly issues server cert using spki" do
        spki = R509::Spki.new(:spki => @spki, :subject=>[['CN','test.local']])
        cert = @ca.sign({ :spki => spki, :profile_name => 'server' })
        cert.to_pem.should match(/BEGIN CERTIFICATE/)
        cert.subject.to_s.should == '/CN=test.local'
        extended_key_usage = cert.extensions['extendedKeyUsage']
        extended_key_usage['value'].should == 'TLS Web Server Authentication'
    end
    it "properly issues server cert" do
        csr = R509::Csr.new(:cert => @cert, :bit_strength => 1024)
        cert = @ca.sign({ :csr => csr, :profile_name => 'server' })
        cert.to_pem.should match(/BEGIN CERTIFICATE/)
        cert.subject.to_s.should == '/C=US/ST=Illinois/L=Chicago/O=Paul Kehrer/CN=langui.sh'
        extended_key_usage = cert.extensions['extendedKeyUsage']
        extended_key_usage['value'].should == 'TLS Web Server Authentication'
    end
    it "when supplied, uses subject_item_policy to determine allowed subject" do
        csr = R509::Csr.new(:cert => @cert, :bit_strength => 512)
        cert = @ca.sign({ :csr => csr, :profile_name => 'server_with_subject_item_policy' })
        #profile requires C, ST, CN. O and OU are optional
        cert.subject.to_s.should == '/C=US/ST=Illinois/O=Paul Kehrer/CN=langui.sh'
    end
    it "raises error when issuing cert with csr that does not match subject_item_policy" do
        csr = R509::Csr.new(:csr => @csr)
        expect { @ca.sign({ :csr => csr, :profile_name => 'server_with_subject_item_policy' }) }.to raise_error(R509::R509Error, /This profile requires you supply/)
    end
    it "issues with specified san domains" do
        csr = R509::Csr.new(:cert => @cert, :bit_strength => 1024)
        data_hash = csr.to_hash
        data_hash[:san_names] = ['langui.sh','domain2.com']
        cert = @ca.sign(:csr => csr, :profile_name => 'server', :data_hash => data_hash )
        cert.san_names.should == ['langui.sh','domain2.com']
    end
    it "issues with san domains from csr" do
        csr = R509::Csr.new(:csr => @csr)
        cert = @ca.sign(:csr => csr, :profile_name => 'server')
        cert.san_names.should == ['test.local','additionaldomains.com','saniam.com']
    end
    it "issues a csr made via array" do
        csr = R509::Csr.new(:subject => [['CN','langui.sh']], :bit_strength => 1024)
        cert = @ca.sign(:csr => csr, :profile_name => 'server')
        cert.subject.to_s.should == '/CN=langui.sh'
    end
    it "issues a cert with the subject array provided" do
        csr = R509::Csr.new(:csr => @csr)
        data_hash = csr.to_hash
        data_hash[:subject]['CN'] = "someotherdomain.com"
        data_hash[:subject].delete("O")
        cert = @ca.sign(:csr => csr, :profile_name => 'server', :data_hash => data_hash )
        cert.subject.to_s.should == '/CN=someotherdomain.com'
    end
    it "tests that policy identifiers are properly encoded" do
        csr = R509::Csr.new(:csr => @csr)
        cert = @ca.sign(:csr => csr, :profile_name => 'server')
        cert.extensions['certificatePolicies']['value'].should == "Policy: 2.16.840.1.12345.1.2.3.4.1\n  CPS: http://example.com/cps\n"
    end
    it "multiple policy identifiers are properly encoded" do
        csr = R509::Csr.new(:csr => @csr)
        config = R509::Config::CaConfig.from_yaml("multi_policy_ca", File.read("#{File.dirname(__FILE__)}/fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"})
        ca = R509::CertificateAuthority::Signer.new(config)
        cert = ca.sign(:csr => csr, :profile_name => 'server')
        cert.extensions['certificatePolicies']['value'].should == "Policy: 2.16.840.1.9999999999.3.0\nPolicy: 2.16.840.1.9999999999.1.2.3.4.1\n  CPS: http://example.com/cps\n"
    end
    it "tests basic constraints CA:TRUE and pathlen:0 on a subroot" do
        csr = R509::Csr.new(:csr => @csr)
        cert = @ca.sign(:csr => csr, :profile_name => 'subroot')
        cert.extensions['basicConstraints']['value'].should == 'CA:TRUE, pathlen:0'
    end
    it "issues with md5" do
        csr = R509::Csr.new(:csr => @csr3)
        cert = @ca.sign(:csr => csr, :profile_name => 'server', :message_digest => 'md5')
        cert.cert.signature_algorithm.should == 'md5WithRSAEncryption'
    end
    it "issues with sha1" do
        csr = R509::Csr.new(:csr => @csr3)
        cert = @ca.sign(:csr => csr, :profile_name => 'server', :message_digest => 'sha1')
        cert.cert.signature_algorithm.should == 'sha1WithRSAEncryption'
    end
    it "issues with sha256" do
        csr = R509::Csr.new(:csr => @csr3)
        cert = @ca.sign(:csr => csr, :profile_name => 'server', :message_digest => 'sha256')
        cert.cert.signature_algorithm.should == 'sha256WithRSAEncryption'
    end
    it "issues with sha512" do
        csr = R509::Csr.new(:csr => @csr3)
        cert = @ca.sign(:csr => csr, :profile_name => 'server', :message_digest => 'sha512')
        cert.cert.signature_algorithm.should == 'sha512WithRSAEncryption'
    end
    it "issues with invalid hash (sha1 fallback)" do
        csr = R509::Csr.new(:csr => @csr3)
        cert = @ca.sign(:csr => csr, :profile_name => 'server', :message_digest => 'invalid')
        cert.cert.signature_algorithm.should == 'sha1WithRSAEncryption'
    end
    it "generates random serial when serial is not specified and uses microtime as part of the serial to prevent collision" do
        now = Time.now
        Time.stub!(:now).and_return(now)
        time = now.to_i.to_s
        csr = R509::Csr.new(:csr => @csr3)
        cert = @ca.sign(:csr => csr, :profile_name => "server")
        cert.serial.to_s.size.should >= 45
        cert.serial.to_s.index(time).should_not be_nil
    end
    it "accepts specified serial number" do
        csr = R509::Csr.new(:csr => @csr3)
        cert = @ca.sign(:csr => csr, :profile_name => "server", :serial => 12345)
        cert.serial.should == 12345
    end
    it "has default notBefore/notAfter dates" do
        not_before = (Time.now - (6 * 60 * 60)).utc
        not_after = (Time.now - (6 * 60 * 60) + (365 * 24 * 60 * 60)).utc
        csr = R509::Csr.new(:csr => @csr3)
        cert = @ca.sign(:csr => csr, :profile_name => "server")
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
        cert = @ca.sign(:csr => csr, :profile_name => "server", :not_before => not_before, :not_after => not_after)
        cert.cert.not_before.ctime.should == not_before.utc.ctime
        cert.cert.not_after.ctime.should == not_after.utc.ctime
    end
    it "issues a certificate from a root that does not have a subjectKeyIdentifier" do
        config = R509::Config::CaConfig.from_yaml("missing_key_identifier_ca", File.read("#{File.dirname(__FILE__)}/fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"})
        ca = R509::CertificateAuthority::Signer.new(config)
        csr = R509::Csr.new(:csr => @csr3)
        cert = ca.sign(:csr => csr, :profile_name => "server")
        cert.extensions['authorityKeyIdentifier'].should == nil
        cert.extended_key_usage.web_server_authentication?.should == true
    end
    it "raises error unless you provide a proper config (or nil)" do
        expect { R509::CertificateAuthority::Signer.new('invalid') }.to raise_error(R509::R509Error, 'config must be a kind of R509::Config::CaConfig or nil (for self-sign only)')
    end
    it "raises error when providing invalid ca profile" do
        csr = R509::Csr.new(:csr => @csr)
        expect { @ca.sign(:csr => csr, :profile_name => 'invalid') }.to raise_error(R509::R509Error, "unknown profile 'invalid'")
    end
    it "raises error when attempting to issue CSR with invalid signature" do
        csr = R509::Csr.new(:csr => @csr_invalid_signature)
        expect { @ca.sign(:csr => csr, :profile_name => 'server') }.to raise_error(R509::R509Error, 'Certificate request signature is invalid.')
    end
    it "raises error when passing non-hash to selfsign method" do
        expect { @ca.selfsign(@csr) }.to raise_error(ArgumentError, "You must pass a hash of options consisting of at minimum :csr")
    end
    it "issues a self-signed certificate with custom fields" do
        not_before = Time.now.to_i
        not_after = Time.now.to_i+3600*24*7300
        csr = R509::Csr.new(
            :subject => [['C','US'],['O','r509 LLC'],['CN','r509 Self-Signed CA Test']],
            :bit_strength => 1024
        )
        cert = @ca.selfsign(
            :csr => csr,
            :serial => 3,
            :not_before => not_before,
            :not_after => not_after,
            :message_digest => 'sha256',
            :san_names => ['sanname1','sanname2']
        )
        cert.public_key.to_s.should == csr.public_key.to_s
        cert.signature_algorithm.should == 'sha256WithRSAEncryption'
        cert.serial.should == 3
        cert.not_before.to_i.should == not_before
        cert.not_after.to_i.should == not_after
        cert.subject.to_s.should == '/C=US/O=r509 LLC/CN=r509 Self-Signed CA Test'
        cert.issuer.to_s.should == '/C=US/O=r509 LLC/CN=r509 Self-Signed CA Test'
        cert.extensions['basicConstraints']['value'].should == 'CA:TRUE'
        cert.san_names.should include('sanname1','sanname2')
    end
    it "issues self-signed certificate with SAN in CSR" do
        csr = R509::Csr.new(
            :subject => [['CN','My Self Sign']],
            :san_names => ['sanname1','sanname2'],
            :bit_strength => 1024
        )
        cert = @ca.selfsign(
            :csr => csr
        )
        cert.san_names.should include('sanname1','sanname2')
        cert.subject.to_s.should == '/CN=My Self Sign'
        cert.issuer.to_s.should == '/CN=My Self Sign'
        cert.public_key.to_s.should == csr.public_key.to_s
    end
    it "issues a self-signed certificate with defaults" do
        csr = R509::Csr.new(
            :subject => [['C','US'],['O','r509 LLC'],['CN','r509 Self-Signed CA Test']],
            :bit_strength => 1024
        )
        cert = @ca.selfsign(
            :csr => csr
        )
        cert.public_key.to_s.should == csr.public_key.to_s
        cert.signature_algorithm.should == 'sha1WithRSAEncryption'
        (cert.not_after.to_i-cert.not_before.to_i).should == 31536000
        cert.subject.to_s.should == '/C=US/O=r509 LLC/CN=r509 Self-Signed CA Test'
        cert.issuer.to_s.should == '/C=US/O=r509 LLC/CN=r509 Self-Signed CA Test'
        cert.extensions['basicConstraints']['value'].should == 'CA:TRUE'
    end
    it "raises an error if attempting to self-sign without a key" do
        csr = R509::Csr.new(:csr => @csr3)
        expect { @ca.selfsign( :csr => csr ) }.to raise_error(ArgumentError, "CSR must also have a private key to self sign")
    end
    it "raises an error if you call sign without passing a config to the object" do
        ca_signer = R509::CertificateAuthority::Signer.new
        csr = R509::Csr.new(:csr => @csr3)
        expect { ca_signer.sign(:csr => csr, :profile_name => "server") }.to raise_error(R509::R509Error, "When instantiating the signer without a config you can only call #selfsign")
    end
end
