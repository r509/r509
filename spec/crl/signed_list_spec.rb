require 'spec_helper'
require 'stringio'

describe R509::CRL::SignedList do
  before :each do
    @crl_reason = TestFixtures::CRL_REASON
    @crl = R509::CRL::SignedList.new(@crl_reason)
    @test_ca_cert = TestFixtures::TEST_CA_CERT
  end

  it "loads a crl with load_from_file" do
    path = File.dirname(__FILE__) + '/../fixtures/crl_with_reason.pem'
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
    @crl.revoked?('111111').should == false
    @crl.revoked?(12345).should == true
    @crl.revoked?('12345').should == true
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
