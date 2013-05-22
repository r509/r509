require 'spec_helper'
require 'stringio'

describe R509::CRL::SignedList do
  before :each do
    @crl_reason = TestFixtures::CRL_REASON
    @crl = R509::CRL::SignedList.new(@crl_reason)
    @test_ca_cert = TestFixtures::TEST_CA_CERT
  end

  it "loads a crl with load_from_file" do
    path = File.dirname(__FILE__) + '/fixtures/crl_with_reason.pem'
    crl = R509::CRL::SignedList.load_from_file path
    crl.revoked[12345].should_not be_nil
  end

  it "returns issuer" do
    @crl.issuer.to_s.should == "/C=US/ST=Illinois/L=Chicago/O=Ruby CA Project/CN=Test CA"
  end

  it "returns last_update" do
    @crl.last_update.should == Time.at(1327446093)
  end

  it "returns next_update" do
    @crl.next_update.should == Time.at(1328054493)
  end

  it "returns signature_algorithm" do
    @crl.signature_algorithm.should == "sha1WithRSAEncryption"
  end

  it "verifies the CRL signature" do
    cert = R509::Cert.new(:cert => @test_ca_cert)
    @crl.verify(cert.public_key).should == true
  end

  it "checks if a serial is revoked?" do
    @crl.revoked?(111111).should == false
    @crl.revoked?(12345).should == true
  end

  it "returns a hash of all revoked certs" do
    @crl.revoked[12345][:time].should == Time.at(1327449693)
    @crl.revoked[12345][:reason].should == "Key Compromise"
    @crl.revoked[123456][:time].should == Time.at(1327449693)
    @crl.revoked[123456][:reason].should == "Unspecified"
    @crl.revoked[1234567][:time].should == Time.at(1327449693)
    @crl.revoked[1234567][:reason].should == "Unspecified"
    @crl.revoked[12345678].should == nil
  end

  it "returns revocation information for a serial" do
    @crl.revoked_cert(11111).should == nil
    revoked_info = @crl.revoked_cert(12345)
    revoked_info[:time].should == Time.at(1327449693)
    revoked_info[:reason].should == "Key Compromise"
  end

  it "returns der" do
    @crl.to_der.should_not be_nil
  end
  it "returns pem" do
    @crl.to_pem.should_not be_nil
  end
  it "writes to pem" do
    sio = StringIO.new
    sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
    @crl.write_pem(sio)
    parsed_crl = R509::CRL::SignedList.new(sio.string)
    parsed_crl.issuer.to_s.should == '/C=US/ST=Illinois/L=Chicago/O=Ruby CA Project/CN=Test CA'
    parsed_crl.issuer.CN.should == 'Test CA'
  end
  it "writes to der" do
    sio = StringIO.new
    sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
    @crl.write_der(sio)
    parsed_crl = R509::CRL::SignedList.new(sio.string)
    parsed_crl.issuer.to_s.should == '/C=US/ST=Illinois/L=Chicago/O=Ruby CA Project/CN=Test CA'
    parsed_crl.issuer.CN.should == 'Test CA'
  end
end

describe R509::CRL::Administrator do
  before :each do
    @cert = TestFixtures::CERT
    @csr = TestFixtures::CSR
    @csr3 = TestFixtures::CSR3
    @test_ca_config = TestFixtures.test_ca_no_profile_config
    @test_ca_dsa_config = TestFixtures.test_ca_dsa_no_profile_config
  end
  it "generates CRL with no entries in revocation list (RSA key)" do
    crl_admin = R509::CRL::Administrator.new(@test_ca_config)
    crl_admin.generate_crl
    crl_admin.crl.to_pem.should match(/BEGIN X509 CRL/)
    crl_admin.crl.signature_algorithm.should == 'sha1WithRSAEncryption'
  end
  it "generates CRL with no entries in revocation list (DSA key)" do
    crl_admin = R509::CRL::Administrator.new(@test_ca_dsa_config)
    crl_admin.generate_crl
    crl_admin.crl.to_pem.should match(/BEGIN X509 CRL/)
    crl_admin.crl.signature_algorithm.should == 'dsaWithSHA1'
  end
  context "elliptic curve", :ec => true do
    before :all do
      @test_ca_ec_config = TestFixtures.test_ca_ec_no_profile_config
    end
    it "generates CRL with no entries in revocation list (EC key)" do
      crl_admin = R509::CRL::Administrator.new(@test_ca_ec_config)
      crl_admin.generate_crl
      crl_admin.crl.to_pem.should match(/BEGIN X509 CRL/)
      crl_admin.crl.signature_algorithm.should == 'ecdsa-with-SHA1'
    end
  end
  it "raises exception when no R509::Config::CAConfig object is passed to the constructor" do
    expect { R509::CRL::Administrator.new(['random']) }.to raise_error(R509::R509Error)
  end
  it "can write the crl_number_file" do
    crl = R509::CRL::Administrator.new(@test_ca_config)
    crl.crl_number_file.string.should == "1"
    crl.crl_number_file.reopen("")
    crl.save_crl_number
    crl.crl_number_file.string.should == "1"
  end
  it "adds a cert to the revocation list" do
    crl_admin = R509::CRL::Administrator.new(@test_ca_config)
    crl_admin.revoked?(383834832).should == false
    crl_admin.revoke_cert(383834832)
    crl_admin.revoked?(383834832).should == true
    crl_admin.crl.revoked[383834832].should_not be_nil
    crl_admin.crl.crl.revoked[0].serial.should == 383834832
  end
  it "can revoke (with reason)" do
    crl_admin = R509::CRL::Administrator.new(@test_ca_config)
    crl_admin.revoked?(12345).should == false
    crl_admin.revoke_cert(12345, 1)
    crl_admin.revoked?(12345).should == true
    crl_admin.revoked_cert(12345)[:reason].should == 1

    crl_admin.crl.crl.revoked[0].serial.should == 12345
    crl_admin.crl.crl.revoked[0].extensions[0].oid.should == "CRLReason"
    crl_admin.crl.crl.revoked[0].extensions[0].value.should == "Key Compromise"
  end
  it "can revoke (without reason)" do
    crl_admin = R509::CRL::Administrator.new(@test_ca_config)
    crl_admin.revoked?(12345).should == false
    crl_admin.revoke_cert(12345)
    crl_admin.revoked?(12345).should == true
    crl_admin.revoked_cert(12345)[:reason].should be_nil

    crl_admin.crl.crl.revoked[0].serial.should == 12345
    crl_admin.crl.crl.revoked[0].extensions.size.should == 0
  end
  it "cannot revoke the same serial twice" do
    crl = R509::CRL::Administrator.new(@test_ca_config)
    crl.revoked?(12345).should == false
    crl.revoke_cert(12345, 1)
    crl.revoked?(12345).should == true
    crl.revoked_cert(12345)[:reason].should == 1
    expect { crl.revoke_cert(12345, 1) }.to raise_error(R509::R509Error, "Cannot revoke a previously revoked certificate")
    crl.revoked?(12345).should == true
  end
  it "adds a cert to the revocation list with an invalid reason code" do
    crl = R509::CRL::Administrator.new(@test_ca_config)
    crl.revoke_cert(383834832,15)
    crl.generate_crl.should match(/BEGIN X509 CRL/)
    crl.revoked?(383834832).should == true
    crl.revoked_cert(383834832)[:reason].should == 0
  end
  it "removes a cert from the revocation list" do
    crl_admin = R509::CRL::Administrator.new(@test_ca_config)
    crl_admin.revoke_cert(383834832)
    crl_admin.revoked?(383834832).should == true
    crl_admin.crl.crl.revoked[0].serial.should == 383834832
    crl_admin.unrevoke_cert(383834832)
    crl_admin.revoked?(383834832).should == false
    crl_admin.crl.crl.revoked.empty?.should == true
  end
  it "loads an existing revocation list file" do
    config = R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert,
      :crl_list_file => TestFixtures::CRL_LIST_FILE
    )
    crl = R509::CRL::Administrator.new(config)
    crl.revoked?(12345).should == true
    crl.revoked_cert(12345)[:revoke_time].should == 1323983885
    crl.revoked_cert(12345)[:reason].should == 0
    crl.revoked?(12346).should == true
    crl.revoked_cert(12346)[:revoke_time].should == 1323983885
    crl.revoked_cert(12346)[:reason].should == nil
  end
  it "when nil crl_list_file still call generate_crl" do
    config = R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert,
      :crl_list_file => nil
    )
    crl_admin = R509::CRL::Administrator.new(config)
    crl_admin.crl.to_pem.should match(/BEGIN X509 CRL/)
  end
  it "sets validity via yaml" do
    crl_admin = R509::CRL::Administrator.new(@test_ca_config)
    now = Time.at Time.now.to_i
    crl_admin.generate_crl
    crl_admin.crl.next_update.should == (now+168*3600) #default 168 hours (7 days)
  end
  it "writes crl list" do
    crl = R509::CRL::Administrator.new(@test_ca_config)
    crl.revoke_cert(12345)
    crl.crl_list_file.string.should match(/[0-9]+,[0-9]+,/)
  end
  it "doesn't write the crl_number_file when it is nil" do
    config = R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert
    )
    crl = R509::CRL::Administrator.new(config)
    expect { crl.save_crl_number }.to_not raise_error(StandardError)
  end
  it "doesn't write the crl_list_file when it is nil" do
    config = R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert
    )
    crl = R509::CRL::Administrator.new(config)
    expect { crl.save_crl_list }.to_not raise_error(StandardError)
  end
end
