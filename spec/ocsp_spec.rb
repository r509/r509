require 'spec_helper'
require 'r509/Ocsp'
require 'openssl'

describe R509::Ocsp::Signer do
    before :all do
        @cert = TestFixtures::CERT
        @stca_cert = TestFixtures::STCA_CERT
        @stca_ocsp_request = TestFixtures::STCA_OCSP_REQUEST
        @ocsp_test_cert = TestFixtures::OCSP_TEST_CERT
        @test_ca_config = TestFixtures.test_ca_config
        @second_ca_config = TestFixtures.second_ca_config
        @ocsp_delegate_config = R509::Config::CaConfig.from_yaml("ocsp_delegate_ca", File.read("#{File.dirname(__FILE__)}/fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"})
        @ocsp_chain_config = R509::Config::CaConfig.from_yaml("ocsp_chain_ca", File.read("#{File.dirname(__FILE__)}/fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"})

    end
    it "rejects ocsp requests from an unknown CA" do
        ocsp_handler = R509::Ocsp::Signer.new( :configs => [@test_ca_config] )
        response = ocsp_handler.handle_request(@stca_ocsp_request)
        response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_UNAUTHORIZED
    end
    it "rejects malformed OCSP requests" do
        ocsp_handler = R509::Ocsp::Signer.new( :configs => [@test_ca_config] )
        response = ocsp_handler.handle_request("notreallyanocsprequest")
        response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_MALFORMEDREQUEST
    end
    it "responds successfully with an OCSP delegate" do
        ocsp_handler = R509::Ocsp::Signer.new( :configs => [@ocsp_delegate_config] )
        csr = R509::Csr.new( :subject => [['CN','ocsptest.r509.local']], :bit_strength => 1024 )
        ca = R509::CertificateAuthority::Signer.new(@test_ca_config)
        cert = ca.sign(:csr => csr, :profile_name => 'server')
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert.cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        response = ocsp_handler.handle_request(ocsp_request)
        response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
        response.verify(@ocsp_delegate_config.ca_cert.cert).should == true
        #TODO Better way to check whether we're adding the certs when signing the basic_response than response size...
        response.to_der.size.should == 1623
    end
    it "responds successfully with an OCSP chain" do
        ocsp_handler = R509::Ocsp::Signer.new( :configs => [@ocsp_chain_config] )
        csr = R509::Csr.new( :subject => [['CN','ocsptest.r509.local']], :bit_strength => 1024 )
        ca = R509::CertificateAuthority::Signer.new(@test_ca_config)
        cert = ca.sign(:csr => csr, :profile_name => 'server')
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert.cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        response = ocsp_handler.handle_request(ocsp_request)
        response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
        response.verify(@ocsp_chain_config.ca_cert.cert).should == true
        #TODO Better way to check whether we're adding the certs when signing the basic_response than response size...
        response.to_der.size.should == 3670
    end
    it "responds successfully from the test_ca" do
        csr = R509::Csr.new( :subject => [['CN','ocsptest.r509.local']], :bit_strength => 1024 )
        ca = R509::CertificateAuthority::Signer.new(@test_ca_config)
        cert = ca.sign(:csr => csr, :profile_name => 'server')
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert.cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        ocsp_handler = R509::Ocsp::Signer.new({ :configs => [@test_ca_config] })
        response = ocsp_handler.handle_request(ocsp_request)
        response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
    end
    it "rejects request with 2 certs from different known CAs" do
        ca = R509::CertificateAuthority::Signer.new(@test_ca_config)

        csr = R509::Csr.new( :subject => [['CN','ocsptest.r509.local']], :bit_strength => 1024 )
        cert = ca.sign(:csr => csr, :profile_name => 'server')

        ca2 = R509::CertificateAuthority::Signer.new(@second_ca_config)

        csr2 = R509::Csr.new( :subject => [['CN','ocsptest2.r509.local']], :bit_strength => 1024 )
        cert2 = ca2.sign(:csr => csr2, :profile_name => 'server')

        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert.cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        certid2 = OpenSSL::OCSP::CertificateId.new(cert2.cert,@second_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid2)

        ocsp_handler = R509::Ocsp::Signer.new({ :configs => [@test_ca_config,@second_ca_config] })
        response = ocsp_handler.handle_request(ocsp_request)
        response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_UNAUTHORIZED
    end
    it "rejects request with 1 cert from known CA and 1 cert from unknown CA" do
        ca = R509::CertificateAuthority::Signer.new(@test_ca_config)

        csr = R509::Csr.new( :subject => [['CN','ocsptest.r509.local']], :bit_strength => 1024 )
        cert = ca.sign(:csr => csr, :profile_name => 'server')

        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert.cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        certid2 = OpenSSL::OCSP::CertificateId.new(OpenSSL::X509::Certificate.new(@cert),OpenSSL::X509::Certificate.new(@stca_cert))
        ocsp_request.add_certid(certid2)

        ocsp_handler = R509::Ocsp::Signer.new({ :configs => [@test_ca_config] })
        response = ocsp_handler.handle_request(ocsp_request)
        response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_UNAUTHORIZED
    end
    it "responds successfully with 2 certs from 1 known CA" do
        ca = R509::CertificateAuthority::Signer.new(@test_ca_config)

        csr = R509::Csr.new( :subject => [['CN','ocsptest.r509.local']], :bit_strength => 1024 )
        cert = ca.sign(:csr => csr, :profile_name => 'server')

        csr2 = R509::Csr.new( :subject => [['CN','ocsptest.r509.local']], :bit_strength => 1024 )
        cert2 = ca.sign(:csr => csr2, :profile_name => 'server')

        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert.cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        certid2 = OpenSSL::OCSP::CertificateId.new(cert2.cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid2)

        ocsp_handler = R509::Ocsp::Signer.new({ :configs => [@test_ca_config] })
        response = ocsp_handler.handle_request(ocsp_request)
        response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
    end
    it "signs an OCSP response properly" do
        cert = OpenSSL::X509::Certificate.new(@ocsp_test_cert)
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        ocsp_handler = R509::Ocsp::Signer.new({ :configs => [@test_ca_config] })
        response = ocsp_handler.handle_request(ocsp_request)
        response.verify(@test_ca_config.ca_cert.cert).should == true
        response.verify(@second_ca_config.ca_cert.cert).should == false
        response.basic.status[0][1].should == OpenSSL::OCSP::V_CERTSTATUS_GOOD
    end
    it "passes in a specific validity checker" do
        class R509::Validity::BogusTestChecker < R509::Validity::Checker
            def check(issuer_fingerprint, serial)
                R509::Validity::Status.new(:status => R509::Validity::REVOKED, :revocation_time => Time.now.to_i)
            end
        end
        cert = OpenSSL::X509::Certificate.new(@ocsp_test_cert)
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        ocsp_handler = R509::Ocsp::Signer.new({ :configs => [@test_ca_config], :validity_checker => R509::Validity::BogusTestChecker.new })
        response = ocsp_handler.handle_request(ocsp_request)
        response.verify(@test_ca_config.ca_cert.cert).should == true
        response.basic.status[0][1].should == OpenSSL::OCSP::V_CERTSTATUS_REVOKED
    end
    it "encodes the proper revocation time in the response" do
        class R509::Validity::BogusTestChecker < R509::Validity::Checker
            def check(issuer_fingerprint, serial)
                R509::Validity::Status.new(:status => R509::Validity::REVOKED, :revocation_time => Time.now.to_i - 3600)
            end
        end
        cert = OpenSSL::X509::Certificate.new(@ocsp_test_cert)
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        ocsp_handler = R509::Ocsp::Signer.new({ :configs => [@test_ca_config], :validity_checker => R509::Validity::BogusTestChecker.new })
        response = ocsp_handler.handle_request(ocsp_request)
        response.basic.status[0][3].to_i.should == Time.now.to_i - 3600
    end
    it "copies nonce from request to response present and equal" do
        cert = OpenSSL::X509::Certificate.new(@ocsp_test_cert)
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        ocsp_request.add_nonce
        ocsp_handler = R509::Ocsp::Signer.new({ :copy_nonce => true, :configs => [@test_ca_config] })
        response = ocsp_handler.handle_request(ocsp_request)
        response.check_nonce(ocsp_request).should == R509::Ocsp::Request::Nonce::PRESENT_AND_EQUAL
    end
    it "doesn't copy nonce if request doesn't have one" do
        cert = OpenSSL::X509::Certificate.new(@ocsp_test_cert)
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        ocsp_handler = R509::Ocsp::Signer.new({ :copy_nonce => true, :configs => [@test_ca_config] })
        response = ocsp_handler.handle_request(ocsp_request)
        response.check_nonce(ocsp_request).should == R509::Ocsp::Request::Nonce::BOTH_ABSENT
    end
    it "has a nonce in the response only" do
        cert = OpenSSL::X509::Certificate.new(@ocsp_test_cert)
        bogus_ocsp_request = OpenSSL::OCSP::Request.new
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        ocsp_request.add_nonce
        ocsp_handler = R509::Ocsp::Signer.new({ :copy_nonce => true, :configs => [@test_ca_config] })
        response = ocsp_handler.handle_request(ocsp_request)
        response.check_nonce(bogus_ocsp_request).should == R509::Ocsp::Request::Nonce::RESPONSE_ONLY
    end
    it "nonce in request and response is not equal" do
        cert = OpenSSL::X509::Certificate.new(@ocsp_test_cert)
        bogus_ocsp_request = OpenSSL::OCSP::Request.new
        bogus_ocsp_request.add_nonce
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        ocsp_request.add_nonce
        ocsp_handler = R509::Ocsp::Signer.new({ :copy_nonce => true, :configs => [@test_ca_config] })
        response = ocsp_handler.handle_request(ocsp_request)
        response.check_nonce(bogus_ocsp_request).should == R509::Ocsp::Request::Nonce::NOT_EQUAL
    end
    it "nonce in request only" do
        cert = OpenSSL::X509::Certificate.new(@ocsp_test_cert)
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        ocsp_request.add_nonce
        ocsp_handler = R509::Ocsp::Signer.new({ :copy_nonce => false, :configs => [@test_ca_config] })
        response = ocsp_handler.handle_request(ocsp_request)
        response.check_nonce(ocsp_request).should == R509::Ocsp::Request::Nonce::REQUEST_ONLY
    end
end

describe R509::Ocsp::Helper::RequestChecker do
    before :all do
        @cert = TestFixtures::CERT
        @test_ca_config = TestFixtures.test_ca_config
        @second_ca_config = TestFixtures.second_ca_config
    end
    it "fails if you don't give it an array of configs" do
        expect { R509::Ocsp::Helper::RequestChecker.new({}, nil) }.to raise_error(R509::R509Error)
    end
    it "fails if you give it an empty array of configs" do
        expect { R509::Ocsp::Helper::RequestChecker.new([], nil) }.to raise_error(R509::R509Error)
    end
    it "fails if you give it a valid config but nil validity checker" do
        expect { R509::Ocsp::Helper::RequestChecker.new([@test_ca_config], nil) }.to raise_error(R509::R509Error)
    end
    it "fails if you give it a valid config but the validity checker doesn't respond to a check method" do
        class FakeChecker
        end
        fake_checker = FakeChecker.new
        expect { R509::Ocsp::Helper::RequestChecker.new([@test_ca_config], fake_checker) }.to raise_error(R509::R509Error)
    end
end

describe R509::Ocsp::Helper::ResponseSigner do
    before :all do
        @cert = TestFixtures::CERT
        @test_ca_config = TestFixtures.test_ca_config
        @second_ca_config = TestFixtures.second_ca_config
    end
    it "fails if you don't give it an array of configs" do
        expect { R509::Ocsp::Helper::ResponseSigner.new({}) }.to raise_error(R509::R509Error)
    end
    it "fails if you give it an empty array of configs" do
        expect { R509::Ocsp::Helper::ResponseSigner.new({:configs=>[]}) }.to raise_error(R509::R509Error)
    end
end

describe R509::Ocsp::Response do
    before :all do
        @ocsp_test_cert = TestFixtures::OCSP_TEST_CERT
        @test_ca_config = TestFixtures.test_ca_config
        @ocsp_response_der = TestFixtures::STCA_OCSP_RESPONSE
    end
    it "raises an exception if you try to pass the wrong type to the constructor" do
        expect { R509::Ocsp::Response.new(@ocsp_response_der) }.to raise_error(R509::R509Error, 'You must pass an OpenSSL::OCSP::Response object to the constructor. See R509::Ocsp::Response.parse if you are trying to parse')
    end
    it "raises an exception if you pass nil to #parse" do
        expect { R509::Ocsp::Response.parse(nil) }.to raise_error(R509::R509Error, 'You must pass a DER encoded OCSP response to this method')
    end
    it "parses a response der and returns the right object on #parse" do
        ocsp_response = R509::Ocsp::Response.parse(@ocsp_response_der)
        ocsp_response.kind_of?(R509::Ocsp::Response).should == true
        ocsp_response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
    end
    it "returns data on to_der" do
        cert = OpenSSL::X509::Certificate.new(@ocsp_test_cert)
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        ocsp_handler = R509::Ocsp::Signer.new({ :configs => [@test_ca_config] })
        response = ocsp_handler.handle_request(ocsp_request)
        response.to_der.should_not == nil
    end
    it "returns a BasicResponse object on #basic" do
        cert = OpenSSL::X509::Certificate.new(@ocsp_test_cert)
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        ocsp_handler = R509::Ocsp::Signer.new({ :configs => [@test_ca_config] })
        response = ocsp_handler.handle_request(ocsp_request)
        response.basic.kind_of?(OpenSSL::OCSP::BasicResponse).should == true
    end
end
