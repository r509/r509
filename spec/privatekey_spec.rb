require 'spec_helper'
require 'r509/PrivateKey'
require 'stringio'

describe R509::PrivateKey do
    before :all do
        @key_csr = TestFixtures::KEY_CSR
        @key_csr_encrypted = TestFixtures::KEY_CSR_ENCRYPTED
        @csr_public_key_modulus = TestFixtures::CSR_PUBLIC_KEY_MODULUS
        @key_csr_der = TestFixtures::KEY_CSR_DER
        @dsa_key = TestFixtures::DSA_KEY
    end
    it "throws an exception when given a type other than DSA or RSA" do
        expect { R509::PrivateKey.new(:type=>:not_rsa_or_dsa) }.to raise_error(ArgumentError)
    end
    it "throws an exception when no hash is provided" do
        expect { R509::PrivateKey.new('string') }.to raise_error(ArgumentError,'Must provide a hash of options')
    end
    it "returns the right value for #rsa?" do
        private_key = R509::PrivateKey.new(:key=>@key_csr)
        private_key.dsa?.should == false
        private_key.rsa?.should == true
    end
    it "returns the right value for #dsa?" do
        private_key = R509::PrivateKey.new(:key => @dsa_key)
        private_key.rsa?.should == false
        private_key.dsa?.should == true
    end
    it "defaults to RSA" do
        private_key = R509::PrivateKey.new(:bit_strength=>1024)
        private_key.key.kind_of?(OpenSSL::PKey::RSA).should == true
    end
    it "loads a pre-existing RSA key" do
        private_key = R509::PrivateKey.new(:key=>@key_csr)
        private_key.to_pem.should == @key_csr
        @key_csr.should_not == nil
    end
    it "generates an RSA key at the default bit strength (2048)" do
        private_key = R509::PrivateKey.new(:type => :rsa)
        private_key.bit_strength.should == 2048
        private_key.key.n.to_i.to_s(2).size.should == 2048
    end
    it "generates an RSA key at a custom bit strength" do
        private_key = R509::PrivateKey.new(:type => :rsa, :bit_strength => 512)
        private_key.bit_strength.should == 512
        private_key.key.n.to_i.to_s(2).size.should == 512
    end
    it "loads a pre-existing DSA key" do
        private_key = R509::PrivateKey.new(:key => @dsa_key)
        private_key.key.kind_of?(OpenSSL::PKey::DSA).should == true
        private_key.key.to_pem.should == @dsa_key
        @dsa_key.should_not == nil
    end
    it "generates a DSA key at the default bit strength (2048)" do
        private_key = R509::PrivateKey.new(:type => :dsa)
        private_key.dsa?.should == true
        private_key.bit_strength.should == 2048
        private_key.key.p.to_i.to_s(2).size.should == 2048
    end
    it "generates a DSA key at a custom bit strength" do
        private_key = R509::PrivateKey.new(:type => :dsa, :bit_strength => 512)
        private_key.bit_strength.should == 512
        private_key.key.p.to_i.to_s(2).size.should == 512
    end
    it "has an exponent of 65537 for new RSA keys" do
        #this test actually checks ruby's underlying libs to make sure they're
        #doing what they're supposed to be doing.
        private_key = R509::PrivateKey.new(:type => :rsa, :bit_strength => 512)
        private_key.key.e.should == 65537
    end
    it "returns the public key" do
        private_key = R509::PrivateKey.new(:key => @key_csr)
        private_key.public_key.n.to_i.should == @csr_public_key_modulus.to_i
    end
    it "returns pem" do
        #load the DER, check that it matches the PEM on to_pem
        private_key = R509::PrivateKey.new(:key => @key_csr_der)
        private_key.to_pem.should == @key_csr
    end
    it "returns der" do
        #load the PEM, check that it matches the DER on to_der
        private_key = R509::PrivateKey.new(:key => @key_csr)
        private_key.to_der.should == @key_csr_der
    end
    it "writes pem" do
        private_key = R509::PrivateKey.new(:key => @key_csr)
        sio = StringIO.new
        sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
        private_key.write_pem(sio)
        sio.string.should == @key_csr
    end
    it "writes der" do
        private_key = R509::PrivateKey.new(:key => @key_csr_der)
        sio = StringIO.new
        sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
        private_key.write_der(sio)
        sio.string.should == @key_csr_der
    end
    it "loads an encrypted private key with the right password" do
        private_key = R509::PrivateKey.new(:key => @key_csr_encrypted, :password => 'Testing1')
        private_key.public_key.n.to_i.should == @csr_public_key_modulus.to_i
    end
    it "fails to load an encrypted private key with wrong password" do
        expect { R509::PrivateKey.new(:key => @key_csr_encrypted, :password => 'wrongPassword') }.to raise_error(R509::R509Error,"Failed to load private key. Invalid key or incorrect password.")
    end
    it "returns an encrypted pem" do
        private_key = R509::PrivateKey.new(:key => @key_csr)
        encrypted_private_key = private_key.to_encrypted_pem('des3','Testing1')
        decrypted_private_key = R509::PrivateKey.new(:key => encrypted_private_key, :password => 'Testing1')
        private_key.to_pem.should == decrypted_private_key.to_pem
    end
    it "writes an encrypted pem" do
        private_key = R509::PrivateKey.new(:key => @key_csr)
        sio = StringIO.new
        sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
        private_key.write_encrypted_pem(sio,'des3','Testing1')
        sio.string.match(/Proc-Type: 4,ENCRYPTED/).should_not == nil
    end
    it "creates an encrypted private key with des3 cipher" do
        private_key = R509::PrivateKey.new(:key => @key_csr)
        sio = StringIO.new
        sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
        private_key.write_encrypted_pem(sio,'des3','Testing1')
        sio.string.match(/DES-EDE3-CBC/).should_not == nil
    end
    it "creates an encrypted private key with aes128 cipher" do
        private_key = R509::PrivateKey.new(:key => @key_csr)
        sio = StringIO.new
        sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
        private_key.write_encrypted_pem(sio,'aes128','Testing1')
        sio.string.match(/AES-128-CBC/).should_not == nil
    end
    it "returns false for in_hardware? when not using an engine" do
        private_key = R509::PrivateKey.new(:key => @key_csr)
        private_key.in_hardware?.should == false
    end
    it "returns true for in_hardware? when an engine is present" do
        engine = double("engine")
        engine.stub(:kind_of?) { |arg|
            (arg == OpenSSL::Engine)?true:false
        }
        key_name = "r509_key"
        key = R509::PrivateKey.new(
            :engine => engine,
            :key_name => key_name
        )
        key.in_hardware?.should == true
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
        engine.stub(:kind_of?) { |arg|
            arg == OpenSSL::Engine
        }
        key_name = "r509_key"
        key = R509::PrivateKey.new(
            :engine => engine,
            :key_name => key_name
        )
        expect { key.to_pem }.to raise_error(R509::R509Error, "This method cannot be called when using keys in hardware")
        expect { key.to_der }.to raise_error(R509::R509Error, "This method cannot be called when using keys in hardware")
        expect { key.to_encrypted_pem('aes256','password') }.to raise_error(R509::R509Error, "This method cannot be called when using keys in hardware")
        expect { key.write_encrypted_pem('/dev/null','aes256','password') }.to raise_error(R509::R509Error, "This method cannot be called when using keys in hardware")
        expect { key.write_der('/dev/null') }.to raise_error(R509::R509Error, "This method cannot be called when using keys in hardware")
    end
    it "loads a hardware key successfully" do
        engine = double("engine")
        engine.stub(:kind_of?) { |arg|
            (arg == OpenSSL::Engine)?true:false
        }
        faux_key = double("faux_key")
        faux_key.stub(:public_key) { "returning public key" }
        engine.stub(:load_private_key) { faux_key }
        key_name = "r509_key"
        engine.should_receive(:load_private_key).with(key_name)
        faux_key.should_receive(:public_key)
        key = R509::PrivateKey.new(
            :engine => engine,
            :key_name => key_name
        )
        key.kind_of?(R509::PrivateKey).should == true
        key.public_key.should == "returning public key"
    end
end

