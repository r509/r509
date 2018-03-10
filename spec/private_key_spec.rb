require 'spec_helper'
require 'r509/private_key'
require 'stringio'

describe R509::PrivateKey do
  before :all do
    @key_csr = TestFixtures::KEY_CSR
    @key_csr_encrypted = TestFixtures::KEY_CSR_ENCRYPTED
    @csr_public_key_modulus = TestFixtures::CSR_PUBLIC_KEY_MODULUS
    @key_csr_der = TestFixtures::KEY_CSR_DER
    @dsa_key = TestFixtures::DSA_KEY
    @ec_key_pem = TestFixtures::EC_KEY1
    @ec_key_der = TestFixtures::EC_KEY1_DER
    @ec_key_encrypted = TestFixtures::EC_KEY1_ENCRYPTED
  end
  it "throws an exception when given a type other than DSA, RSA, or EC" do
    expect { R509::PrivateKey.new(:type => :not_rsa_or_dsa) }.to raise_error(ArgumentError)
  end
  it "throws an exception when no hash is provided" do
    expect { R509::PrivateKey.new('string') }.to raise_error(ArgumentError, 'Must provide a hash of options')
  end
  it "returns the right value for #rsa?" do
    private_key = R509::PrivateKey.new(:key => @key_csr)
    expect(private_key.dsa?).to eq(false)
    expect(private_key.ec?).to eq(false)
    expect(private_key.rsa?).to eq(true)
  end
  it "returns the right value for #dsa?" do
    private_key = R509::PrivateKey.new(:key => @dsa_key)
    expect(private_key.rsa?).to eq(false)
    expect(private_key.ec?).to eq(false)
    expect(private_key.dsa?).to eq(true)
  end
  it "generates a default 2048-bit RSA key when nothing is passed to the constructor" do
    private_key = R509::PrivateKey.new
    expect(private_key.rsa?).to eq(true)
    expect(private_key.bit_length).to eq(2048)
    expect(private_key.bit_strength).to eq(2048)
  end
  it "defaults to RSA" do
    private_key = R509::PrivateKey.new(:bit_length => 1024)
    expect(private_key.key.is_a?(OpenSSL::PKey::RSA)).to eq(true)
  end
  it "loads a pre-existing RSA key" do
    private_key = R509::PrivateKey.new(:key => @key_csr)
    expect(private_key.to_pem).to eq(@key_csr)
    expect(@key_csr).not_to be_nil
  end
  it "generates an RSA key at the default bit length (2048)" do
    private_key = R509::PrivateKey.new(:type => "rsa")
    expect(private_key.bit_length).to eq(2048)
    expect(private_key.key.n.to_i.to_s(2).size).to eq(2048)
  end
  it "generates an RSA key at a custom bit length" do
    private_key = R509::PrivateKey.new(:type => "rsa", :bit_length => 512)
    expect(private_key.bit_length).to eq(512)
    expect(private_key.key.n.to_i.to_s(2).size).to eq(512)
  end
  it "loads a pre-existing DSA key" do
    private_key = R509::PrivateKey.new(:key => @dsa_key)
    expect(private_key.key.is_a?(OpenSSL::PKey::DSA)).to eq(true)
    expect(private_key.key.to_pem).to eq(@dsa_key)
    expect(@dsa_key).not_to be_nil
  end
  it "generates a DSA key at the default bit length (2048)" do
    private_key = R509::PrivateKey.new(:type => "dsa")
    expect(private_key.dsa?).to eq(true)
    expect(private_key.bit_length).to eq(2048)
    expect(private_key.key.p.to_i.to_s(2).size).to eq(2048)
  end
  it "generates a DSA key at a custom bit length" do
    private_key = R509::PrivateKey.new(:type => "dsa", :bit_length => 512)
    expect(private_key.bit_length).to eq(512)
    expect(private_key.key.p.to_i.to_s(2).size).to eq(512)
  end
  it "has an exponent of 65537 for new RSA keys" do
    # this test actually checks ruby's underlying libs to make sure they're
    # doing what they're supposed to be doing.
    private_key = R509::PrivateKey.new(:type => "rsa", :bit_length => 512)
    expect(private_key.key.e).to eq(65537)
  end
  it "returns the public key" do
    private_key = R509::PrivateKey.new(:key => @key_csr)
    expect(private_key.public_key.n.to_i).to eq(@csr_public_key_modulus.to_i)
  end
  it "returns pem" do
    # load the DER, check that it matches the PEM on to_pem
    private_key = R509::PrivateKey.new(:key => @key_csr_der)
    expect(private_key.to_pem).to eq(@key_csr)
  end
  it "returns der" do
    # load the PEM, check that it matches the DER on to_der
    private_key = R509::PrivateKey.new(:key => @key_csr)
    expect(private_key.to_der).to eq(@key_csr_der)
  end
  it "writes pem" do
    private_key = R509::PrivateKey.new(:key => @key_csr)
    sio = StringIO.new
    sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
    private_key.write_pem(sio)
    expect(sio.string).to eq(@key_csr)
  end
  it "writes der" do
    private_key = R509::PrivateKey.new(:key => @key_csr_der)
    sio = StringIO.new
    sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
    private_key.write_der(sio)
    expect(sio.string).to eq(@key_csr_der)
  end
  it "loads an encrypted private key with the right password" do
    private_key = R509::PrivateKey.new(:key => @key_csr_encrypted, :password => 'Testing1')
    expect(private_key.public_key.n.to_i).to eq(@csr_public_key_modulus.to_i)
  end
  it "fails to load an encrypted private key with wrong password" do
    expect { R509::PrivateKey.new(:key => @key_csr_encrypted, :password => 'wrongPassword') }.to raise_error(R509::R509Error, "Failed to load private key. Invalid key or incorrect password.")
  end
  it "returns an encrypted pem" do
    private_key = R509::PrivateKey.new(:key => @key_csr)
    encrypted_private_key = private_key.to_encrypted_pem('des3', 'Testing1')
    decrypted_private_key = R509::PrivateKey.new(:key => encrypted_private_key, :password => 'Testing1')
    expect(private_key.to_pem).to eq(decrypted_private_key.to_pem)
  end
  it "writes an encrypted pem" do
    private_key = R509::PrivateKey.new(:key => @key_csr)
    sio = StringIO.new
    sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
    private_key.write_encrypted_pem(sio, 'des3', 'Testing1')
    expect(sio.string.match(/Proc-Type: 4,ENCRYPTED/)).not_to be_nil
  end
  it "creates an encrypted private key with des3 cipher" do
    private_key = R509::PrivateKey.new(:key => @key_csr)
    sio = StringIO.new
    sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
    private_key.write_encrypted_pem(sio, 'des3', 'Testing1')
    expect(sio.string.match(/DES-EDE3-CBC/)).not_to be_nil
  end
  it "creates an encrypted private key with aes128 cipher" do
    private_key = R509::PrivateKey.new(:key => @key_csr)
    sio = StringIO.new
    sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
    private_key.write_encrypted_pem(sio, 'aes128', 'Testing1')
    expect(sio.string.match(/AES-128-CBC/)).not_to be_nil
  end
  it "returns false for in_hardware? when not using an engine" do
    private_key = R509::PrivateKey.new(:key => @key_csr)
    expect(private_key.in_hardware?).to eq(false)
  end
  it "returns true for in_hardware? when an engine is present" do
    engine = double("engine")
    expect(engine).to receive(:is_a?).with(OpenSSL::Engine).and_return(true)
    key_name = "r509_key"
    key = R509::PrivateKey.new(
      :engine => engine,
      :key_name => key_name
    )
    expect(key.in_hardware?).to eq(true)
  end
  it "raises an error if you provide engine and key" do
    expect { R509::PrivateKey.new(:key => @key_csr, :engine => 'not really an engine') }.to raise_error(ArgumentError, "You can't pass both :key and :engine")
  end
  it "raises an error if you provide a key_name with no engine" do
    expect { R509::PrivateKey.new(:key_name => 'my_key') }.to raise_error(ArgumentError, 'When providing a :key_name you MUST provide an :engine')
  end
  it "raises an error when providing an engine with no key_name" do
    expect { R509::PrivateKey.new(:engine => 'engine_goes_here') }.to raise_error(ArgumentError, 'When providing an :engine you MUST provide a :key_name')
  end
  it "raises an error if engine is not an OpenSSL::Engine" do
    expect { R509::PrivateKey.new(:key_name => 'my_key', :engine => 'not really an engine') }.to raise_error(ArgumentError, 'When providing an engine, it must be of type OpenSSL::Engine')
  end
  it "raises an error if you call output methods (pem,der,write) when using a hardware key" do
    engine = double("engine")
    expect(engine).to receive(:is_a?).with(OpenSSL::Engine).and_return(true)
    key_name = "r509_key"
    key = R509::PrivateKey.new(
      :engine => engine,
      :key_name => key_name
    )
    expect { key.to_pem }.to raise_error(R509::R509Error, "This method cannot be called when using keys in hardware")
    expect { key.to_der }.to raise_error(R509::R509Error, "This method cannot be called when using keys in hardware")
    expect { key.to_encrypted_pem('aes256', 'password') }.to raise_error(R509::R509Error, "This method cannot be called when using keys in hardware")
    expect { key.write_encrypted_pem('/dev/null', 'aes256', 'password') }.to raise_error(R509::R509Error, "This method cannot be called when using keys in hardware")
    expect { key.write_der('/dev/null') }.to raise_error(R509::R509Error, "This method cannot be called when using keys in hardware")
  end
  it "loads a hardware key successfully" do
    engine = double("engine")
    expect(engine).to receive(:is_a?).with(OpenSSL::Engine).and_return(true)
    faux_key = double("faux_key")
    expect(faux_key).to receive(:public_key).and_return("returning public key")
    key_name = "r509_key"
    expect(engine).to receive(:load_private_key).with(key_name).and_return(faux_key)
    key = R509::PrivateKey.new(
      :engine => engine,
      :key_name => key_name
    )
    expect(key.is_a?(R509::PrivateKey)).to eq(true)
    expect(key.public_key).to eq("returning public key")
  end
  it "loads a private key with load_from_file" do
    path = File.dirname(__FILE__) + '/fixtures/key4.pem'
    key = R509::PrivateKey.load_from_file path
    expect(key.rsa?).to eq(true)
  end
  it "loads a private key with load_from_file with password" do
    path = File.dirname(__FILE__) + '/fixtures/key4_encrypted_des3.pem'
    key = R509::PrivateKey.load_from_file(path, 'r509')
    expect(key.rsa?).to eq(true)
  end

  it "returns an error for curve_name for dsa/rsa" do
    private_key = R509::PrivateKey.new(:key => @key_csr)
    expect { private_key.curve_name }.to raise_error(R509::R509Error, 'Curve name is only available with EC private keys')
  end

  context "elliptic curves", :ec => true do
    it "loads a pre-existing EC key" do
      private_key = R509::PrivateKey.new(:key => @ec_key_pem)
      expect(private_key.to_pem).to eq(@ec_key_pem)
      expect(@ec_key_pem).not_to be_nil
    end

    it "loads an encrypted private key with the right password" do
      private_key = R509::PrivateKey.new(:key => @ec_key_encrypted, :password => 'Testing1')
      expect(private_key.to_pem).to eq(@ec_key_pem)
      expect(@ec_key_encrypted).not_to be_nil
      expect(@ec_key_pem).not_to be_nil
    end

    it "returns the right value for #ec?" do
      path = File.dirname(__FILE__) + '/fixtures/ec_key1.der'
      private_key = R509::PrivateKey.load_from_file path
      expect(private_key.rsa?).to eq(false)
      expect(private_key.dsa?).to eq(false)
      expect(private_key.ec?).to eq(true)
    end

    it "returns the curve_name" do
      private_key = R509::PrivateKey.new(:key => @ec_key_pem)
      expect(private_key.curve_name).to eq('secp384r1')
    end

    it "generates an elliptic curve key using the default curve (secp384r1)" do
      private_key = R509::PrivateKey.new(:type => "ec")
      expect(private_key.curve_name).to eq('secp384r1')
    end

    it "generates an elliptic curve key using a specified curve" do
      private_key = R509::PrivateKey.new(:type => "ec", :curve_name => 'sect283r1')
      expect(private_key.curve_name).to eq('sect283r1')
    end

    it "returns the public key" do
      private_key = R509::PrivateKey.new(:key => @ec_key_pem)
      public_key = private_key.public_key
      expect(public_key.public_key?).to eq(true)
      expect(public_key.private_key?).to eq(false)
    end

    it "returns the pem" do
      private_key = R509::PrivateKey.new(:key => @ec_key_pem)
      expect(private_key.to_pem).to eq(@ec_key_pem)
    end

    it "returns the der" do
      private_key = R509::PrivateKey.new(:key => @ec_key_pem)
      expect(private_key.to_der).to eq(@ec_key_der)
    end

    it "returns the bit-length" do
      private_key = R509::PrivateKey.new(:key => @ec_key_pem)
      expect(private_key.bit_length).to eq(384)
    end

  end
end
