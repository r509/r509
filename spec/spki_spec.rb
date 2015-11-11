require 'spec_helper'
require 'stringio'
require 'r509/spki'

shared_examples_for "create spki with private key" do
  it "generates a spki with default digest" do
    spki = R509::SPKI.new(:key => @key)
    expect(spki.to_pem).not_to be_nil
    spki.verify_signature
  end

  it "generates a spki from a pem key" do
    spki = R509::SPKI.new(:key => @key.to_pem)
    expect(spki.to_pem).not_to be_nil
    spki.verify_signature
  end

  it "generates a spki with custom digest" do
    spki = R509::SPKI.new(:key => @key, :message_digest => "sha256")
    expect(spki.to_pem).not_to be_nil
    case
    when @key.rsa?
      expect(spki.signature_algorithm).to(match(/sha256/i))
    when @key.dsa?
      expect(spki.signature_algorithm).to(match(/sha1/i))
    end
    spki.verify_signature
  end

  it "stores the key" do
    spki = R509::SPKI.new(:key => @key)
    expect(spki.key).to eq(@key)
  end

  it "verifies signature" do
    spki = R509::SPKI.new(:key => @key)
    spki.verify_signature
  end
end

shared_examples_for "spki + private key" do
  it "verifies they match" do
    expect { R509::SPKI.new(:key => @key, :spki => @spki) }.to_not raise_error
  end

  it "returns the correct signature_algorithm" do
    spki = R509::SPKI.new(:spki => @spki, :key => @key)
    case
    when @key.rsa?
      expect(spki.signature_algorithm).to(match(/RSA/i))
    when @key.dsa?
      expect(spki.signature_algorithm).to(match(/DSA/i))
    when @key.ec?
      expect(spki.signature_algorithm).to(match(/ecdsa/i))
    end
  end

  it "errors if they don't match" do
    expect { R509::SPKI.new(:key => @key, :spki => @spki2) }.to raise_error(R509::R509Error, 'Key does not match SPKI.')
  end
end

describe R509::SPKI do
  before :all do
    # also known as SPKAC (signed public key and challenge)
    @spki_dsa = TestFixtures::SPKI_DSA
    @spki_dsa_no_verify = TestFixtures::SPKI_DSA_NO_VERIFY
    @spki = TestFixtures::SPKI
    @spki_rsa_newlines = TestFixtures::SPKI_RSA_NEWLINES
    @spki_ec = TestFixtures::SPKI_EC
    @spki_der = TestFixtures::SPKI_DER
  end
  it "raises an error if you don't provide a hash" do
    expect { R509::SPKI.new("junk") }.to raise_error(ArgumentError, 'Must provide a hash of options')
  end
  it "raises an error if you provide an empty hash" do
    expect { R509::SPKI.new({}) }.to raise_error(ArgumentError, 'Must provide either :spki or :key')
  end
  context "rsa" do
    context "no existing spki" do
      before :all do
        @key = R509::PrivateKey.new(:type => "rsa", :bit_length => 1024)
      end
      include_examples "create spki with private key"
    end
    context "existing spki + private key" do
      before :all do
        @key = R509::PrivateKey.new(:type => "rsa", :bit_length => 512)
        @key2 = R509::PrivateKey.new(:type => "rsa", :bit_length => 512)
        @spki = R509::SPKI.new(:key => @key).to_pem
        @spki2 = R509::SPKI.new(:key => @key2).to_pem
      end
      include_examples "spki + private key"
    end
  end
  context "dsa" do
    context "no existing spki" do
      before :all do
        @key = R509::PrivateKey.new(:type => "dsa", :bit_length => 1024)
      end
      include_examples "create spki with private key"
    end
    context "existing spki + private key" do
      before :all do
        @key = R509::PrivateKey.new(:type => "dsa", :bit_length => 512)
        @key2 = R509::PrivateKey.new(:type => "dsa", :bit_length => 512)
        @spki = R509::SPKI.new(:key => @key).to_pem
        @spki2 = R509::SPKI.new(:key => @key2).to_pem
      end
      include_examples "spki + private key"
    end
  end
  context "elliptic curve", :ec => true do
    context "no existing spki" do
      before :all do
        @key = R509::PrivateKey.new(:type => "EC")
      end
      include_examples "create spki with private key"
    end
    context "existing spki + private key" do
      before :all do
        @key = R509::PrivateKey.new(:type => "ec")
        @key2 = R509::PrivateKey.new(:type => "ec")
        @spki = R509::SPKI.new(:key => @key).to_pem
        @spki2 = R509::SPKI.new(:key => @key2).to_pem
      end
      include_examples "spki + private key"
    end
  end
  context "with existing spki" do
    it "loads an RSA spki" do
      spki = R509::SPKI.new(:spki => @spki)
      expect(spki.to_pem).to eq(@spki)
    end
    it "loads an spkac with newlines" do
      spki = R509::SPKI.new(:spki => @spki_rsa_newlines)
      expect(spki.to_pem).to eq(@spki_rsa_newlines.gsub("\n", ""))
    end
    it "properly strips SPKAC= prefix and loads" do
      spki = R509::SPKI.new(:spki => "SPKAC=" + @spki)
      expect(spki.to_pem).to eq(@spki)
    end
  end
  it "returns the public key" do
    spki = R509::SPKI.new(:spki => @spki)
    expect(spki.public_key).not_to be_nil
  end
  it "returns pem" do
    spki = R509::SPKI.new(:spki => @spki)
    expect(spki.to_pem).to eq(@spki)
  end
  it "returns der" do
    spki = R509::SPKI.new(:spki => @spki)
    expect(spki.to_der).to eq(@spki_der)
  end
  it "writes to pem" do
    spki = R509::SPKI.new(:spki => @spki)
    sio = StringIO.new
    sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
    spki.write_pem(sio)
    expect(sio.string).to eq(@spki)
  end
  it "writes to der" do
    spki = R509::SPKI.new(:spki => @spki)
    sio = StringIO.new
    sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
    spki.write_der(sio)
    expect(sio.string).to eq(@spki_der)
  end
  it "rsa?" do
    spki = R509::SPKI.new(:spki => @spki)
    expect(spki.rsa?).to eq(true)
    expect(spki.dsa?).to eq(false)
  end
  it "returns error when asking for curve_name on non-ec" do
    spki = R509::SPKI.new(:spki => @spki)
    expect { spki.curve_name }.to raise_error(R509::R509Error, 'Curve name is only available with EC')
  end
  it "returns RSA key algorithm for RSA" do
    spki = R509::SPKI.new(:spki => @spki)
    expect(spki.key_algorithm).to eq("RSA")
  end
  it "gets RSA bit length" do
    spki = R509::SPKI.new(:spki => @spki)
    expect(spki.bit_length).to eq(2048)
    expect(spki.bit_strength).to eq(2048)
  end
  it "loads a DSA spkac" do
    spki = R509::SPKI.new(:spki => @spki_dsa)
    expect(spki.to_pem).to eq(@spki_dsa)
  end
  it "gets DSA bit length" do
    spki = R509::SPKI.new(:spki => @spki_dsa)
    expect(spki.bit_length).to eq(2048)
  end
  it "dsa?" do
    spki = R509::SPKI.new(:spki => @spki_dsa)
    expect(spki.dsa?).to eq(true)
    expect(spki.rsa?).to eq(false)
  end
  it "returns DSA key algorithm for DSA" do
    spki = R509::SPKI.new(:spki => @spki_dsa)
    expect(spki.key_algorithm).to eq("DSA")
  end

  context "elliptic curve", :ec => true do
    it "loads an spkac" do
      spki = R509::SPKI.new(:spki => @spki_ec)
      expect(spki.to_pem).to eq(@spki_ec)
    end
    it "returns the curve name" do
      spki = R509::SPKI.new(:spki => @spki_ec)
      expect(spki.curve_name).to eq('secp384r1')
    end
    it "gets ECDSA bit length" do
      spki = R509::SPKI.new(:spki => @spki_ec)
      expect(spki.bit_length).to eq(384)
    end
    it "returns the key algorithm" do
      spki = R509::SPKI.new(:spki => @spki_ec)
      expect(spki.key_algorithm).to eq("EC")
    end
    it "returns the public key" do
      spki = R509::SPKI.new(:spki => @spki_ec)
      expect(spki.public_key).not_to be_nil
    end
    it "ec?" do
      spki = R509::SPKI.new(:spki => @spki_ec)
      expect(spki.ec?).to eq(true)
      expect(spki.dsa?).to eq(false)
      expect(spki.rsa?).to eq(false)
    end
  end

  context "when elliptic curve support is unavailable" do
    before :all do
      @ec = OpenSSL::PKey.send(:remove_const, :EC) # remove EC support for test!
      load('r509/openssl/ec-hack.rb')
    end
    after :all do
      OpenSSL::PKey.send(:remove_const, :EC) # remove stubbed EC
      OpenSSL::PKey::EC = @ec # add the real one back
    end
    it "checks rsa?" do
      spki = R509::SPKI.new(:spki => @spki)
      expect(spki.rsa?).to eq(true)
      expect(spki.ec?).to eq(false)
      expect(spki.dsa?).to eq(false)
    end
    it "returns RSA key algorithm for RSA CSR" do
      spki = R509::SPKI.new(:spki => @spki)
      expect(spki.key_algorithm).to eq("RSA")
    end
  end
end
