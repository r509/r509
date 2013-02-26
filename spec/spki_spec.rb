require 'spec_helper'
require 'stringio'
require 'r509/spki'

shared_examples_for "create spki with private key" do
    it "generates a spki with default digest" do
      spki = R509::SPKI.new(:key => @key)
      spki.to_pem.should_not be_nil
      spki.verify_signature
    end

    it "generates a spki from a pem key" do
      spki = R509::SPKI.new(:key => @key.to_pem)
      spki.to_pem.should_not be_nil
      spki.verify_signature
    end

    it "generates a spki with custom digest" do
      spki = R509::SPKI.new(:key => @key, :message_digest => "sha256")
      spki.to_pem.should_not be_nil
      spki.verify_signature
    end

    it "stores the key" do
      spki = R509::SPKI.new(:key => @key)
      spki.key.should == @key
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

  it "errors if they don't match" do
      expect { R509::SPKI.new(:key => @key, :spki => @spki2) }.to raise_error(R509::R509Error,'Key does not match SPKI.')
  end
end

describe R509::SPKI do
  before :all do
    #also known as SPKAC (signed public key and challenge)
    @spki_dsa = TestFixtures::SPKI_DSA
    @spki_dsa_no_verify = TestFixtures::SPKI_DSA_NO_VERIFY
    @spki = TestFixtures::SPKI
    @spki_rsa_newlines = TestFixtures::SPKI_RSA_NEWLINES
    @spki_ec = TestFixtures::SPKI_EC
    @spki_der = TestFixtures::SPKI_DER
  end
  it "raises an error if you don't provide a hash" do
    expect { R509::SPKI.new("junk") }.to raise_error(ArgumentError,'Must provide a hash of options')
  end
  it "raises an error if you provide an empty hash" do
    expect { R509::SPKI.new({}) }.to raise_error(ArgumentError,'Must provide either :spki or :key')
  end
  context "rsa" do
    context "no existing spki" do
      before :all do
        @key = R509::PrivateKey.new(:type => :rsa, :bit_strength => 1024)
      end
      include_examples "create spki with private key"
    end
    context "existing spki + private key" do
      before :all do
        @key = R509::PrivateKey.new(:type => :rsa, :bit_strength => 512)
        @key2 = R509::PrivateKey.new(:type => :rsa, :bit_strength => 512)
        @spki = R509::SPKI.new(:key => @key).to_pem
        @spki2 = R509::SPKI.new(:key => @key2).to_pem
      end
      include_examples "spki + private key"
    end
  end
  context "dsa" do
    context "no existing spki" do
      before :all do
        @key = R509::PrivateKey.new(:type => :dsa, :bit_strength => 1024)
      end
      include_examples "create spki with private key"
    end
    context "existing spki + private key" do
      before :all do
        @key = R509::PrivateKey.new(:type => :dsa, :bit_strength => 512)
        @key2 = R509::PrivateKey.new(:type => :dsa, :bit_strength => 512)
        @spki = R509::SPKI.new(:key => @key).to_pem
        @spki2 = R509::SPKI.new(:key => @key2).to_pem
      end
      include_examples "spki + private key"
    end
  end
  context "elliptic curve" do
    context "no existing spki" do
      before :all do
        @key = R509::PrivateKey.new(:type => :ec)
      end
      include_examples "create spki with private key"
    end
    context "existing spki + private key" do
      before :all do
        @key = R509::PrivateKey.new(:type => :ec)
        @key2 = R509::PrivateKey.new(:type => :ec)
        @spki = R509::SPKI.new(:key => @key).to_pem
        @spki2 = R509::SPKI.new(:key => @key2).to_pem
      end
      include_examples "spki + private key"
    end
  end
  context "with existing spki" do
    it "loads an RSA spki" do
      spki = R509::SPKI.new( :spki => @spki )
      spki.to_pem.should == @spki
    end
    it "loads an spkac with newlines" do
      spki = R509::SPKI.new( :spki => @spki_rsa_newlines )
      spki.to_pem.should == @spki_rsa_newlines.gsub("\n","")
    end
    it "properly strips SPKAC= prefix and loads" do
      spki = R509::SPKI.new( :spki => "SPKAC="+@spki )
      spki.to_pem.should == @spki
    end
  end
  it "returns the public key" do
    spki = R509::SPKI.new( :spki => @spki )
    spki.public_key.should_not == nil
  end
  it "returns pem" do
    spki = R509::SPKI.new( :spki => @spki )
    spki.to_pem.should == @spki
  end
  it "returns der" do
    spki = R509::SPKI.new( :spki => @spki )
    spki.to_der.should == @spki_der
  end
  it "writes to pem" do
    spki = R509::SPKI.new( :spki => @spki )
    sio = StringIO.new
    sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
    spki.write_pem(sio)
    sio.string.should == @spki
  end
  it "writes to der" do
    spki = R509::SPKI.new( :spki => @spki )
    sio = StringIO.new
    sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
    spki.write_der(sio)
    sio.string.should ==  @spki_der
  end
  it "rsa?" do
    spki = R509::SPKI.new( :spki => @spki )
    spki.rsa?.should == true
    spki.dsa?.should == false
  end
  it "returns error when asking for curve_name on non-ec" do
    spki = R509::SPKI.new( :spki => @spki )
    expect { spki.curve_name }.to raise_error(R509::R509Error,'Curve name is only available with EC SPKIs')
  end
  it "returns RSA key algorithm for RSA" do
    spki = R509::SPKI.new( :spki => @spki )
    spki.key_algorithm.should == :rsa
  end
  it "gets RSA bit strength" do
    spki = R509::SPKI.new( :spki => @spki )
    spki.bit_strength.should == 2048
  end
  it "loads a DSA spkac" do
    spki = R509::SPKI.new( :spki => @spki_dsa )
    spki.to_pem.should == @spki_dsa
  end
  it "gets DSA bit strength" do
    spki = R509::SPKI.new( :spki => @spki_dsa )
    spki.bit_strength.should == 2048
  end
  it "dsa?" do
    spki = R509::SPKI.new( :spki => @spki_dsa )
    spki.dsa?.should == true
    spki.rsa?.should == false
  end
  it "returns DSA key algorithm for DSA" do
    spki = R509::SPKI.new( :spki => @spki_dsa )
    spki.key_algorithm.should == :dsa
  end

  context "elliptic curve" do
    it "loads an spkac" do
      spki = R509::SPKI.new( :spki => @spki_ec )
      spki.to_pem.should == @spki_ec
    end
    it "returns the curve name" do
      spki = R509::SPKI.new( :spki => @spki_ec )
      spki.curve_name.should == 'secp384r1'
    end
    it "raises error on bit strength" do
      spki = R509::SPKI.new( :spki => @spki_ec )
      expect { spki.bit_strength }.to raise_error(R509::R509Error,'Bit strength is not available for EC at this time.')
    end
    it "returns the key algorithm" do
      spki = R509::SPKI.new( :spki => @spki_ec )
      spki.key_algorithm.should == :ec
    end
    it "returns the public key" do
      spki = R509::SPKI.new( :spki => @spki_ec )
      spki.public_key.should_not == nil
    end
    it "ec?" do
      spki = R509::SPKI.new( :spki => @spki_ec )
      spki.ec?.should == true
      spki.dsa?.should == false
      spki.rsa?.should == false
    end
  end
end
