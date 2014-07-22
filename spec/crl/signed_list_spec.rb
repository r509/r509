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
    expect(crl.revoked[12345]).not_to be_nil
  end

  it "returns issuer" do
    expect(@crl.issuer.to_s).to eq("/C=US/ST=Illinois/L=Chicago/O=Ruby CA Project/CN=Test CA")
  end

  it "returns last_update" do
    expect(@crl.last_update).to eq(Time.at(1327446093))
  end

  it "returns next_update" do
    expect(@crl.next_update).to eq(Time.at(1328054493))
  end

  it "returns signature_algorithm" do
    expect(@crl.signature_algorithm).to eq("sha1WithRSAEncryption")
  end

  it "verifies the CRL signature" do
    cert = R509::Cert.new(:cert => @test_ca_cert)
    expect(@crl.verify(cert.public_key)).to eq(true)
  end

  it "checks if a serial is revoked?" do
    expect(@crl.revoked?(111111)).to eq(false)
    expect(@crl.revoked?('111111')).to eq(false)
    expect(@crl.revoked?(12345)).to eq(true)
    expect(@crl.revoked?('12345')).to eq(true)
  end

  it "returns a hash of all revoked certs" do
    expect(@crl.revoked[12345][:time]).to eq(Time.at(1327449693))
    expect(@crl.revoked[12345][:reason]).to eq("Key Compromise")
    expect(@crl.revoked[123456][:time]).to eq(Time.at(1327449693))
    expect(@crl.revoked[123456][:reason]).to eq("Unspecified")
    expect(@crl.revoked[1234567][:time]).to eq(Time.at(1327449693))
    expect(@crl.revoked[1234567][:reason]).to eq("Unspecified")
    expect(@crl.revoked[12345678]).to be_nil
  end

  it "returns revocation information for a serial" do
    expect(@crl.revoked_cert(11111)).to be_nil
    revoked_info = @crl.revoked_cert(12345)
    expect(revoked_info[:time]).to eq(Time.at(1327449693))
    expect(revoked_info[:reason]).to eq("Key Compromise")
  end

  it "returns der" do
    expect(@crl.to_der).not_to be_nil
  end
  it "returns pem" do
    expect(@crl.to_pem).not_to be_nil
  end
  it "writes to pem" do
    sio = StringIO.new
    sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
    @crl.write_pem(sio)
    parsed_crl = R509::CRL::SignedList.new(sio.string)
    expect(parsed_crl.issuer.to_s).to eq('/C=US/ST=Illinois/L=Chicago/O=Ruby CA Project/CN=Test CA')
    expect(parsed_crl.issuer.CN).to eq('Test CA')
  end
  it "writes to der" do
    sio = StringIO.new
    sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
    @crl.write_der(sio)
    parsed_crl = R509::CRL::SignedList.new(sio.string)
    expect(parsed_crl.issuer.to_s).to eq('/C=US/ST=Illinois/L=Chicago/O=Ruby CA Project/CN=Test CA')
    expect(parsed_crl.issuer.CN).to eq('Test CA')
  end
end
