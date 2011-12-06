require 'spec_helper'
require 'stringio'

describe R509::Crl do
    before :each do
        @cert = TestFixtures::CERT
        @csr = TestFixtures::CSR
        @csr3 = TestFixtures::CSR3
        @test_ca_config = TestFixtures.test_ca_config
    end
    it "generates a crl and returns pem from an existing revocation list" do
        crl = R509::Crl.new(@test_ca_config)
        crl.generate_crl
        crl.to_pem.should match(/BEGIN X509 CRL/)
    end
    it "returns der on to_der" do
        crl = R509::Crl.new(@test_ca_config)
        crl.generate_crl
        crl.to_der.should_not == ''
    end
    it "adds a cert to the revocation list" do
        crl = R509::Crl.new(@test_ca_config)
        crl.revoke_cert(383834832)
        crl.generate_crl.should match(/BEGIN X509 CRL/)
    crl.revoked?(383834832).should == true
    end
    it "removes a cert from the revocation list" do
        crl = R509::Crl.new(@test_ca_config)
        crl.unrevoke_cert(383834832)
        crl.generate_crl
    crl.revoked?(383834832).should == false
    end
    it "sets validity period properly through the setter" do
        crl = R509::Crl.new(@test_ca_config)
    # TODO : Is this kind of behavior redundant? Should they just be
    #   setting things on the config object?
        crl.validity_hours = 2
        now = Time.at Time.now.to_i
        crl.generate_crl
        crl.next_update.should == (now+2*3600)
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
        crl.last_update.should == now
    end
    it "writes to pem (improve me)" do
        crl = R509::Crl.new(@test_ca_config)
        crl.generate_crl
    sio = StringIO.new
    sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
        crl.write_pem(sio)
        sio.string.should_not == ''
    end
    it "writes to der (improve me)" do
        crl = R509::Crl.new(@test_ca_config)
        crl.generate_crl
    sio = StringIO.new
    sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
        crl.write_der(sio)
        sio.string.should_not == ''
    end
end
