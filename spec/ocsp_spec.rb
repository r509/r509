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
    end
    it "rejects ocsp requests from an unknown CA" do
        ocsp_handler = R509::Ocsp::Signer.new([@test_ca_config])
        statuses = ocsp_handler.check_request(@stca_ocsp_request)
        response = ocsp_handler.sign_response(statuses)
        response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_UNAUTHORIZED
    end
    it "responds successfully from the test_ca" do
        csr = R509::Csr.new
        csr.create_with_subject [['CN','ocsptest.r509.local']]
        ca = R509::Ca.new(@test_ca_config)
        cert = ca.sign_cert(csr,'server')
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert.cert,@test_ca_config.ca_cert)
        ocsp_request.add_certid(certid)
        ocsp_handler = R509::Ocsp::Signer.new([@test_ca_config])
        statuses = ocsp_handler.check_request(ocsp_request)
        response = ocsp_handler.sign_response(statuses)
        response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
    end
    it "rejects request with 2 certs from different known CAs" do
        ca = R509::Ca.new(@test_ca_config)

        csr = R509::Csr.new
        csr.create_with_subject [['CN','ocsptest.r509.local']]
        cert = ca.sign_cert(csr,'server')

        ca2 = R509::Ca.new(@second_ca_config)

        csr2 = R509::Csr.new
        csr2.create_with_subject [['CN','ocsptest2.r509.local']]
        cert2 = ca2.sign_cert(csr2,'server')

        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert.cert,@test_ca_config.ca_cert)
        ocsp_request.add_certid(certid)
        certid2 = OpenSSL::OCSP::CertificateId.new(cert2.cert,@second_ca_config.ca_cert)
        ocsp_request.add_certid(certid2)

        ocsp_handler = R509::Ocsp::Signer.new([@test_ca_config,@second_ca_config])
        statuses = ocsp_handler.check_request(ocsp_request)
        response = ocsp_handler.sign_response(statuses)
        response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_UNAUTHORIZED
    end
    it "rejects request with 1 cert from known CA and 1 cert from unknown CA" do
        ca = R509::Ca.new(@test_ca_config)

        csr = R509::Csr.new
        csr.create_with_subject [['CN','ocsptest.r509.local']]
        cert = ca.sign_cert(csr,'server')

        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert.cert,@test_ca_config.ca_cert)
        ocsp_request.add_certid(certid)
        certid2 = OpenSSL::OCSP::CertificateId.new(OpenSSL::X509::Certificate.new(@cert),OpenSSL::X509::Certificate.new(@stca_cert))
        ocsp_request.add_certid(certid2)

        ocsp_handler = R509::Ocsp::Signer.new([@test_ca_config])
        statuses = ocsp_handler.check_request(ocsp_request)
        response = ocsp_handler.sign_response(statuses)
        response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_UNAUTHORIZED
    end
    it "responds successfully with 2 certs from 1 known CA" do
        ca = R509::Ca.new(@test_ca_config)

        csr = R509::Csr.new
        csr.create_with_subject [['CN','ocsptest.r509.local']]
        cert = ca.sign_cert(csr,'server')

        csr2 = R509::Csr.new
        csr2.create_with_subject [['CN','ocsptest.r509.local']]
        cert2 = ca.sign_cert(csr2,'server')

        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert.cert,@test_ca_config.ca_cert)
        ocsp_request.add_certid(certid)
        certid2 = OpenSSL::OCSP::CertificateId.new(cert2.cert,@test_ca_config.ca_cert)
        ocsp_request.add_certid(certid2)

        ocsp_handler = R509::Ocsp::Signer.new([@test_ca_config])
        statuses = ocsp_handler.check_request(ocsp_request)
        response = ocsp_handler.sign_response(statuses)
        response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
    end
    it "signs an OCSP response properly" do
        cert = OpenSSL::X509::Certificate.new(@ocsp_test_cert)
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert,@test_ca_config.ca_cert)
        ocsp_request.add_certid(certid)
        ocsp_handler = R509::Ocsp::Signer.new([@test_ca_config])
        statuses = ocsp_handler.check_request(ocsp_request)
        response = ocsp_handler.sign_response(statuses)
        #TODO: learn what this really means
        #and how to suppress the output when it doesn't match
        #/Users/pkehrer/Code/r509/spec/ocsp_spec.rb:107: warning: error:27069076:OCSP routines:OCSP_basic_verify:signer certificate not found
        store = OpenSSL::X509::Store.new
        store.add_cert(@test_ca_config.ca_cert)
        response.basic.verify([@test_ca_config.ca_cert],store).should == true
    end
end

describe R509::Ocsp::Helper::RequestChecker do
    before :all do
        @cert = TestFixtures::CERT
        @stca_cert = TestFixtures::STCA_CERT
        @stca_ocsp_request = TestFixtures::STCA_OCSP_REQUEST
        @test_ca_config = TestFixtures.test_ca_config
        @second_ca_config = TestFixtures.second_ca_config
    end
    it "fails if you don't give it an array of configs" do
        expect { R509::Ocsp::Helper::RequestChecker.new({}) }.to raise_error(R509::R509Error)
    end
    it "fails if you give it an empty array of configs" do
        expect { R509::Ocsp::Helper::RequestChecker.new([]) }.to raise_error(R509::R509Error)
    end
end

describe R509::Ocsp::Helper::ResponseSigner do
    before :all do
        @cert = TestFixtures::CERT
        @stca_cert = TestFixtures::STCA_CERT
        @stca_ocsp_request = TestFixtures::STCA_OCSP_REQUEST
        @test_ca_config = TestFixtures.test_ca_config
        @second_ca_config = TestFixtures.second_ca_config
    end
    it "fails if you don't give it an array of configs" do
        expect { R509::Ocsp::Helper::ResponseSigner.new({}) }.to raise_error(R509::R509Error)
    end
    it "fails if you give it an empty array of configs" do
        expect { R509::Ocsp::Helper::ResponseSigner.new([]) }.to raise_error(R509::R509Error)
    end
end

