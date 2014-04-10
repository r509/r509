require 'spec_helper'

shared_examples_for "a correct R509 KeyUsage object" do |critical|
  before :each do
    extension_name = "keyUsage"
    klass = R509::Cert::Extensions::KeyUsage
    ef = OpenSSL::X509::ExtensionFactory.new
    openssl_ext = ef.create_extension(extension_name, @extension_value, critical)
    @r509_ext = klass.new(openssl_ext)
  end

  it "allowed_uses should be non-nil critical:#{critical}" do
    @r509_ext.allowed_uses.should_not == nil
  end

  it "allowed_uses should be correct critical:#{critical}" do
    @r509_ext.allowed_uses.should == @allowed_uses
  end

  it "the individual allowed-use functions should be correct critical:#{critical}" do
    @r509_ext.digital_signature?.should == @allowed_uses.include?(R509::Cert::Extensions::KeyUsage::AU_DIGITAL_SIGNATURE)
    @r509_ext.non_repudiation?.should == @allowed_uses.include?(R509::Cert::Extensions::KeyUsage::AU_NON_REPUDIATION)
    @r509_ext.key_encipherment?.should == @allowed_uses.include?(R509::Cert::Extensions::KeyUsage::AU_KEY_ENCIPHERMENT)
    @r509_ext.data_encipherment?.should == @allowed_uses.include?(R509::Cert::Extensions::KeyUsage::AU_DATA_ENCIPHERMENT)
    @r509_ext.key_agreement?.should == @allowed_uses.include?(R509::Cert::Extensions::KeyUsage::AU_KEY_AGREEMENT)
    @r509_ext.key_cert_sign?.should == @allowed_uses.include?(R509::Cert::Extensions::KeyUsage::AU_KEY_CERT_SIGN)
    @r509_ext.crl_sign?.should == @allowed_uses.include?(R509::Cert::Extensions::KeyUsage::AU_CRL_SIGN)
    @r509_ext.encipher_only?.should == @allowed_uses.include?(R509::Cert::Extensions::KeyUsage::AU_ENCIPHER_ONLY)
    @r509_ext.decipher_only?.should == @allowed_uses.include?(R509::Cert::Extensions::KeyUsage::AU_DECIPHER_ONLY)
  end

  it "the #allows? method should work critical:#{critical}" do
    @allowed_uses.each do |au|
      @r509_ext.allows?(au).should == true
    end
  end

  it "reports #critical? properly" do
    @r509_ext.critical?.should == critical
  end
end

describe R509::Cert::Extensions::KeyUsage do
  context "validate key usage" do
    it "errors with non-array" do
      expect { R509::Cert::Extensions::KeyUsage.new('not an array') }.to raise_error(ArgumentError, 'You must pass a hash with a key :value that contains an array of strings (see README)')
    end

    it "errors with nil" do
      expect { R509::Cert::Extensions::KeyUsage.new(nil) }.to raise_error(ArgumentError, 'You must pass a hash with a key :value that contains an array of strings (see README)')
    end

    it "errors with hash with no :value" do
      expect { R509::Cert::Extensions::KeyUsage.new({}) }.to raise_error(ArgumentError, 'You must pass a hash with a key :value that contains an array of strings (see README)')
    end

    it "errors with hash with non-array :value" do
      expect { R509::Cert::Extensions::KeyUsage.new(:value => "string") }.to raise_error(ArgumentError, 'You must pass a hash with a key :value that contains an array of strings (see README)')
    end
  end

  context "KeyUsage" do
    context "creation & yaml generation" do
      context "single KU" do
        before :all do
          @args = { :value => ['digitalSignature'] }
          @ku = R509::Cert::Extensions::KeyUsage.new(@args)
        end

        it "creates extension" do
          @ku.allowed_uses.should == ['digitalSignature']
        end

        it "builds yaml" do
          YAML.load(@ku.to_yaml).should == @args.merge(:critical => false)
        end
      end

      context "multiple KU" do
        before :all do
          @args = { :value => ['digitalSignature','keyAgreement'] }
          @ku = R509::Cert::Extensions::KeyUsage.new(@args)
        end

        it "creates extension" do
          @ku.allowed_uses.should == ['digitalSignature','keyAgreement']
        end

        it "builds_yaml" do
          YAML.load(@ku.to_yaml).should == @args.merge(:critical => false)
        end
      end

      context "default criticality" do
        before :all do
          @args = { :value => ['keyAgreement'] }
          @ku = R509::Cert::Extensions::KeyUsage.new(@args)
        end

        it "creates extension" do
          @ku.critical?.should be_false
        end

        it "builds yaml" do
          YAML.load(@ku.to_yaml).should == @args.merge(:critical => false)
        end
      end

      context "non-default criticality" do
        before :all do
          @args = { :value => ['keyAgreement'], :critical => true }
          @ku = R509::Cert::Extensions::KeyUsage.new(@args)
        end

        it "creates extension" do
          @ku.critical?.should be_true
        end

        it "builds yaml" do
          YAML.load(@ku.to_yaml).should == @args
        end
      end

    end

    context "with one allowed use" do
      before :all do
        @allowed_uses = [ R509::Cert::Extensions::KeyUsage::AU_DIGITAL_SIGNATURE ]
        @extension_value = @allowed_uses.join(", ")
      end

      it_should_behave_like "a correct R509 KeyUsage object", false
      it_should_behave_like "a correct R509 KeyUsage object", true
    end

    context "with some allowed uses" do
      before :all do
        # this spec and the one below alternate the uses
        @allowed_uses = [ R509::Cert::Extensions::KeyUsage::AU_DIGITAL_SIGNATURE, R509::Cert::Extensions::KeyUsage::AU_KEY_ENCIPHERMENT, R509::Cert::Extensions::KeyUsage::AU_KEY_AGREEMENT, R509::Cert::Extensions::KeyUsage::AU_CRL_SIGN, R509::Cert::Extensions::KeyUsage::AU_DECIPHER_ONLY ]
        @extension_value = @allowed_uses.join(", ")
      end

      it_should_behave_like "a correct R509 KeyUsage object", false
      it_should_behave_like "a correct R509 KeyUsage object", true
    end

    context "with some different allowed uses" do
      before :all do
        @allowed_uses = [ R509::Cert::Extensions::KeyUsage::AU_NON_REPUDIATION, R509::Cert::Extensions::KeyUsage::AU_DATA_ENCIPHERMENT, R509::Cert::Extensions::KeyUsage::AU_KEY_CERT_SIGN, R509::Cert::Extensions::KeyUsage::AU_ENCIPHER_ONLY ]
        @extension_value = @allowed_uses.join(", ")
      end

      it_should_behave_like "a correct R509 KeyUsage object", false
      it_should_behave_like "a correct R509 KeyUsage object", true
    end

    context "with all allowed uses" do
      before :all do
        @allowed_uses = [
          R509::Cert::Extensions::KeyUsage::AU_DIGITAL_SIGNATURE,
          R509::Cert::Extensions::KeyUsage::AU_NON_REPUDIATION,
          R509::Cert::Extensions::KeyUsage::AU_KEY_ENCIPHERMENT,
          R509::Cert::Extensions::KeyUsage::AU_DATA_ENCIPHERMENT,
          R509::Cert::Extensions::KeyUsage::AU_KEY_AGREEMENT,
          R509::Cert::Extensions::KeyUsage::AU_KEY_CERT_SIGN,
          R509::Cert::Extensions::KeyUsage::AU_CRL_SIGN,
          R509::Cert::Extensions::KeyUsage::AU_ENCIPHER_ONLY,
          R509::Cert::Extensions::KeyUsage::AU_DECIPHER_ONLY
        ]
        @extension_value = @allowed_uses.join(", ")
      end

      it_should_behave_like "a correct R509 KeyUsage object", false
      it_should_behave_like "a correct R509 KeyUsage object", true
    end
  end
end
