require 'spec_helper'
require 'stringio'
require 'r509/spki'


describe R509::Spki do
  before :all do
    #also known as SPKAC (signed public key and challenge)
    @spki_dsa = TestFixtures::SPKI_DSA.strip
    @spki = TestFixtures::SPKI.strip
    @spki_rsa_newlines = TestFixtures::SPKI_RSA_NEWLINES
    @spki_ec = TestFixtures::SPKI_EC
    @spki_der = TestFixtures::SPKI_DER
  end
  it "raises an error if you don't provide a hash" do
    expect { R509::Spki.new("junk") }.to raise_error(ArgumentError,'Must provide a hash of options')
  end
  it "loads an RSA spkac" do
    spki = R509::Spki.new( :spki => @spki )
    spki.to_pem.should == @spki
  end
  it "loads an spkac with newlines" do
    spki = R509::Spki.new( :spki => @spki_rsa_newlines )
    spki.to_pem.should == @spki_rsa_newlines.gsub("\n","")
  end
  it "properly strips SPKAC= prefix and loads" do
    spki = R509::Spki.new( :spki => "SPKAC="+@spki )
    spki.to_pem.should == @spki
  end
  it "returns the public key" do
    spki = R509::Spki.new( :spki => @spki )
    spki.public_key.should_not == nil
  end
  it "returns pem" do
    spki = R509::Spki.new( :spki => @spki )
    spki.to_pem.should == @spki
  end
  it "returns der" do
    spki = R509::Spki.new( :spki => @spki )
    spki.to_der.should == @spki_der
  end
  it "writes to pem" do
    spki = R509::Spki.new( :spki => @spki )
    sio = StringIO.new
    sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
    spki.write_pem(sio)
    sio.string.should == @spki
  end
  it "writes to der" do
    spki = R509::Spki.new( :spki => @spki )
    sio = StringIO.new
    sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
    spki.write_der(sio)
    sio.string.should ==  @spki_der
  end
  it "rsa?" do
    spki = R509::Spki.new( :spki => @spki )
    spki.rsa?.should == true
    spki.dsa?.should == false
  end
  it "returns RSA key algorithm for RSA" do
    spki = R509::Spki.new( :spki => @spki )
    spki.key_algorithm.should == :rsa
  end
  it "gets RSA bit strength" do
    spki = R509::Spki.new( :spki => @spki )
    spki.bit_strength.should == 2048
  end
  it "loads a DSA spkac" do
    spki = R509::Spki.new( :spki => @spki_dsa )
    spki.to_pem.should == @spki_dsa
  end
  it "gets DSA bit strength" do
    spki = R509::Spki.new( :spki => @spki_dsa )
    spki.bit_strength.should == 2048
  end
  it "dsa?" do
    spki = R509::Spki.new( :spki => @spki_dsa )
    spki.dsa?.should == true
    spki.rsa?.should == false
  end
  it "returns DSA key algorithm for DSA" do
    spki = R509::Spki.new( :spki => @spki_dsa )
    spki.key_algorithm.should == :dsa
  end

  context "elliptic curve" do
    it "loads an spkac" do
      spki = R509::Spki.new( :spki => @spki_ec )
      spki.to_pem.should == @spki_ec
    end
    it "returns the curve name" do
      spki = R509::Spki.new( :spki => @spki_ec )
      spki.curve_name.should == 'secp384r1'
    end
    it "raises error on bit strength" do
      spki = R509::Spki.new( :spki => @spki_ec )
      expect { spki.bit_strength }.to raise_error(R509::R509Error,'Bit strength is not available for EC at this time.')
    end
    it "returns the key algorithm" do
      spki = R509::Spki.new( :spki => @spki_ec )
      spki.key_algorithm.should == :ec
    end
    it "returns the public key" do
      spki = R509::Spki.new( :spki => @spki_ec )
      spki.public_key.should_not == nil
    end
    it "ec?" do
      spki = R509::Spki.new( :spki => @spki_ec )
      spki.ec?.should == true
      spki.dsa?.should == false
      spki.rsa?.should == false
    end
  end
end
