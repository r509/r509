require 'spec_helper'
require 'stringio'

describe R509::Crl do
    before :each do
        @cert = TestFixtures::CERT
        @csr = TestFixtures::CSR
        @csr3 = TestFixtures::CSR3
        @test_ca_config = TestFixtures.test_ca_config
    end
    it "generates CRL with no entries in revocation list" do
        crl = R509::Crl.new(@test_ca_config)
        crl.generate_crl
        crl.to_pem.should match(/BEGIN X509 CRL/)
    end
    it "raises exception when no R509::Config object is passed to the constructor" do
        expect { R509::Crl.new(['random']) }.to raise_error(R509::R509Error)
    end
    it "can write the crl_number_file" do
        crl = R509::Crl.new(@test_ca_config)
        crl.crl_number_file.string.should == "1"
        crl.crl_number_file.reopen("")
        crl.save_crl_number
        crl.crl_number_file.string.should == "1"
    end
    it "adds a cert to the revocation list" do
        crl = R509::Crl.new(@test_ca_config)
        crl.revoked?(383834832).should == false
        crl.revoke_cert(383834832)
        crl.revoked?(383834832).should == true
        parsed_crl = OpenSSL::X509::CRL.new(crl.to_pem)
        parsed_crl.revoked[0].serial.should == 383834832
    end
    it "can revoke (with reason)" do
        crl = R509::Crl.new(@test_ca_config)
        crl.revoked?(12345).should == false
        crl.revoke_cert(12345, 1)
        crl.revoked?(12345).should == true
        crl.revoked_cert(12345)[:reason].should == 1

        parsed_crl = OpenSSL::X509::CRL.new(crl.to_pem)
        parsed_crl.revoked[0].serial.should == 12345
        parsed_crl.revoked[0].extensions[0].oid.should == "CRLReason"
        parsed_crl.revoked[0].extensions[0].value.should == "Key Compromise"
    end
    it "cannot revoke the same serial twice" do
        crl = R509::Crl.new(@test_ca_config)
        crl.revoked?(12345).should == false
        crl.revoke_cert(12345, 1)
        crl.revoked?(12345).should == true
        crl.revoked_cert(12345)[:reason].should == 1
        expect { crl.revoke_cert(12345, 1) }.to raise_error(R509::R509Error, "Cannot revoke a previously revoked certificate")
        crl.revoked?(12345).should == true
    end
    it "adds a cert to the revocation list with an invalid reason code" do
        crl = R509::Crl.new(@test_ca_config)
        crl.revoke_cert(383834832,15)
        crl.generate_crl.should match(/BEGIN X509 CRL/)
        crl.revoked?(383834832).should == true
        crl.revoked_cert(383834832)[:reason].should == 0
    end
    it "removes a cert from the revocation list" do
        crl = R509::Crl.new(@test_ca_config)
        crl.revoke_cert(383834832)
        crl.revoked?(383834832).should == true
        parsed_crl = OpenSSL::X509::CRL.new(crl.to_pem)
        parsed_crl.revoked[0].serial.should == 383834832
        crl.unrevoke_cert(383834832)
        crl.revoked?(383834832).should == false
        parsed_crl = OpenSSL::X509::CRL.new(crl.to_pem)
        parsed_crl.revoked.empty?.should == true
    end
    it "loads an existing revocation list file" do
        config = R509::Config.new(
            :ca_cert => TestFixtures.test_ca_cert,
            :crl_list_file => TestFixtures::CRL_LIST_FILE
        )
        crl = R509::Crl.new(config)
        crl.revoked?(12345).should == true
        crl.revoked_cert(12345)[:revoke_time].should == 1323983885
        crl.revoked_cert(12345)[:reason].should == 0

    end
    it "when nil crl_list_file still call generate_crl" do
        config = R509::Config.new(
            :ca_cert => TestFixtures.test_ca_cert,
            :crl_list_file => nil
        )
        crl = R509::Crl.new(config)
        crl.to_pem.should match(/BEGIN X509 CRL/)
    end
    it "sets validity via yaml" do
        crl = R509::Crl.new(@test_ca_config)
        now = Time.at Time.now.to_i
        crl.generate_crl
        crl.next_update.should == (now+168*3600) #default 168 hours (7 days)
    end
    it "has a last_update time" do
        crl = R509::Crl.new(@test_ca_config)
        now = Time.at Time.now.to_i
        crl.generate_crl
        crl.last_update.should == (now - @test_ca_config.crl_start_skew_seconds)
    end
    it "returns der" do
        crl = R509::Crl.new(@test_ca_config)
        crl.generate_crl
        parsed_crl = OpenSSL::X509::CRL.new(crl.to_der)
        parsed_crl.issuer.to_s.should == '/C=US/ST=Illinois/L=Chicago/O=Ruby CA Project/CN=Test CA'
    end
    it "returns pem" do
        crl = R509::Crl.new(@test_ca_config)
        crl.generate_crl
        parsed_crl = OpenSSL::X509::CRL.new(crl.to_pem)
        parsed_crl.issuer.to_s.should == '/C=US/ST=Illinois/L=Chicago/O=Ruby CA Project/CN=Test CA'
    end
    it "writes to pem" do
        crl = R509::Crl.new(@test_ca_config)
        crl.generate_crl
        sio = StringIO.new
        sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
        crl.write_pem(sio)
        parsed_crl = OpenSSL::X509::CRL.new(sio.string)
        parsed_crl.issuer.to_s.should == '/C=US/ST=Illinois/L=Chicago/O=Ruby CA Project/CN=Test CA'
    end
    it "writes to der" do
        crl = R509::Crl.new(@test_ca_config)
        crl.generate_crl
        sio = StringIO.new
        sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
        crl.write_der(sio)
        parsed_crl = OpenSSL::X509::CRL.new(sio.string)
        parsed_crl.issuer.to_s.should == '/C=US/ST=Illinois/L=Chicago/O=Ruby CA Project/CN=Test CA'
    end
    it "writes crl list" do
        crl = R509::Crl.new(@test_ca_config)
        crl.revoke_cert(12345)
        crl.save_crl_list
        crl.crl_list_file.string.should match(/[0-9]+,[0-9]+,[0-9]+,[0-9]+,[0-9]+/)
    end
    it "doesn't write the crl_number_file when it is nil" do
        config = R509::Config.new(
            :ca_cert => TestFixtures.test_ca_cert
        )
        crl = R509::Crl.new(config)
        expect { crl.save_crl_number }.to_not raise_error(StandardError)
    end
    it "doesn't write the crl_list_file when it is nil" do
        config = R509::Config.new(
            :ca_cert => TestFixtures.test_ca_cert
        )
        crl = R509::Crl.new(config)
        expect { crl.save_crl_list }.to_not raise_error(StandardError)
    end
end
