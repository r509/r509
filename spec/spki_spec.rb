require 'spec_helper'
require 'stringio'
require 'r509/spki'


describe R509::Spki do
    before :all do
        #also known as SPKAC (signed public key and challenge)
        @spki_dsa = TestFixtures::SPKI_DSA.strip
        @spki = TestFixtures::SPKI.strip
        @spki_der = TestFixtures::SPKI_DER
    end
    it "raises an error if you don't provide a hash" do
        expect { R509::Spki.new("junk") }.to raise_error(ArgumentError,'Must provide a hash of options')
    end
    it "raises an error if you don't provide spki and subject" do
        expect { R509::Spki.new(:spki => @spki) }.to raise_error(ArgumentError,'Must provide both spki and subject')
    end
    it "raises an error if you don't provide an Array for san_names" do
        expect { R509::Spki.new(:spki => @spki, :subject => [['CN','test']], :san_names => "hello.com") }.to raise_error(ArgumentError,'if san_names are provided they must be in an Array')
    end
    it "loads an RSA spkac" do
        spki = R509::Spki.new( :spki => @spki, :subject => [['CN','spkitest.com']] )
        spki.to_pem.should == @spki
    end
    it "properly strips SPKAC= prefix and loads" do
        spki = R509::Spki.new(
            :spki => "SPKAC="+@spki,
            :subject => [['CN','spkitest.com']]
        )
        spki.to_pem.should == @spki
    end
    it "returns the public key" do
        spki = R509::Spki.new(
            :spki => @spki,
            :subject => [['CN','spkitest.com']]
        )
        spki.public_key.should_not == nil
    end
    it "returns pem" do
        spki = R509::Spki.new(
            :spki => @spki,
            :subject => [['CN','spkitest.com']]
        )
        spki.to_pem.should == @spki
    end
    it "returns der" do
        spki = R509::Spki.new(
            :spki => @spki,
            :subject => [['CN','spkitest.com']]
        )
        spki.to_der.should == @spki_der
    end
    it "writes to pem" do
        spki = R509::Spki.new(
            :spki => @spki,
            :subject => [['CN','spkitest.com']]
        )
        sio = StringIO.new
        sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
        spki.write_pem(sio)
        sio.string.should == @spki
    end
    it "writes to der" do
        spki = R509::Spki.new(
            :spki => @spki,
            :subject => [['CN','spkitest.com']]
        )
        sio = StringIO.new
        sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
        spki.write_der(sio)
        sio.string.should ==  @spki_der
    end
    it "rsa?" do
        spki = R509::Spki.new(
            :spki => @spki,
            :subject => [['CN','spkitest.com']]
        )
        spki.rsa?.should == true
        spki.dsa?.should == false
    end
    it "returns RSA key algorithm for RSA" do
        spki = R509::Spki.new(
            :spki => @spki,
            :subject => [['CN','spkitest.com']]
        )
        spki.key_algorithm.should == "RSA"
    end
    it "gets RSA bit strength" do
        spki = R509::Spki.new(
            :spki => @spki,
            :subject => [['CN','spkitest.com']]
        )
        spki.bit_strength.should == 2048
    end
    it "loads a DSA spkac" do
        spki = R509::Spki.new(
            :spki => @spki_dsa,
            :subject => [['CN','spkitest.com']]
        )
        spki.to_pem.should == @spki_dsa
    end
    it "gets DSA bit strength" do
        spki = R509::Spki.new(
            :spki => @spki_dsa,
            :subject => [['CN','spkitest.com']]
        )
        spki.bit_strength.should == 2048
    end
    it "dsa?" do
        spki = R509::Spki.new(
            :spki => @spki_dsa,
            :subject => [['CN','spkitest.com']]
        )
        spki.dsa?.should == true
        spki.rsa?.should == false
    end
    it "returns DSA key algorithm for DSA" do
        spki = R509::Spki.new(
            :spki => @spki_dsa,
            :subject => [['CN','spkitest.com']]
        )
        spki.key_algorithm.should == "DSA"
    end
    it "returns expected value for subject" do
        spki = R509::Spki.new(
            :spki => @spki,
            :subject => [['CN','spkitest.com']]
        )
        spki.subject.to_s.should == '/CN=spkitest.com'
    end
    it "returns expected value for san names" do
        spki = R509::Spki.new(
            :spki => @spki,
            :subject => [['CN','spkitest.com']],
            :san_names => ['domain1.com','domain2.com']
        )
        spki.san_names.should == ['domain1.com','domain2.com']
    end
    it "returns empty array when passed no san_names" do
        spki = R509::Spki.new(
            :spki => @spki,
            :subject => [['CN','spkitest.com']]
        )
        spki.san_names.empty?.should == true
    end
    it "creates a valid hash object with to_hash" do
        spki = R509::Spki.new(
            :spki => @spki,
            :subject => [['CN','spkitest.com']],
            :san_names => ["test.local"]
        )
        spki.to_hash[:subject].kind_of?(R509::Subject).should == true
        spki.to_hash[:subject].to_s.should == '/CN=spkitest.com'
        spki.to_hash[:san_names].should == ["test.local"]
    end
end
