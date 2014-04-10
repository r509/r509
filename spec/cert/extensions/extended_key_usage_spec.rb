require 'spec_helper'

include R509::Cert::Extensions

shared_examples_for "a correct R509 ExtendedKeyUsage object" do |critical|
  before :all do
    extension_name = "extendedKeyUsage"
    klass = ExtendedKeyUsage
    ef = OpenSSL::X509::ExtensionFactory.new
    openssl_ext = ef.create_extension( extension_name, @extension_value , critical )
    @r509_ext = klass.new( openssl_ext )
  end

  it "allowed_uses should be non-nil critical:#{critical}" do
    @r509_ext.allowed_uses.should_not == nil
  end

  it "allowed_uses should be correct critical:#{critical}" do
    @r509_ext.allowed_uses.should == @allowed_uses
  end

  it "the individual allowed-use functions should be correct critical:#{critical}" do
    @r509_ext.web_server_authentication?.should == @allowed_uses.include?( ExtendedKeyUsage::AU_WEB_SERVER_AUTH )
    @r509_ext.web_client_authentication?.should == @allowed_uses.include?( ExtendedKeyUsage::AU_WEB_CLIENT_AUTH )
    @r509_ext.code_signing?.should == @allowed_uses.include?( ExtendedKeyUsage::AU_CODE_SIGNING )
    @r509_ext.email_protection?.should == @allowed_uses.include?( ExtendedKeyUsage::AU_EMAIL_PROTECTION )
    @r509_ext.ocsp_signing?.should == @allowed_uses.include?( ExtendedKeyUsage::AU_OCSP_SIGNING )
    @r509_ext.time_stamping?.should == @allowed_uses.include?( ExtendedKeyUsage::AU_TIME_STAMPING )
    @r509_ext.any_extended_key_usage?.should == @allowed_uses.include?( ExtendedKeyUsage::AU_ANY_EXTENDED_KEY_USAGE )
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


describe R509::Cert::Extensions::ExtendedKeyUsage do
  include R509::Cert::Extensions

  context "validate extended key usage" do
    it "errors with non-array" do
      expect { R509::Cert::Extensions::ExtendedKeyUsage.new( 'not an array' ) }.to raise_error(ArgumentError, 'You must pass a hash with a key :value that contains an array of strings (see README)')
    end

    it "errors with nil" do
      expect { R509::Cert::Extensions::ExtendedKeyUsage.new(nil) }.to raise_error(ArgumentError, 'You must pass a hash with a key :value that contains an array of strings (see README)')
    end

    it "errors with hash with no :value" do
      expect { R509::Cert::Extensions::ExtendedKeyUsage.new({}) }.to raise_error(ArgumentError, 'You must pass a hash with a key :value that contains an array of strings (see README)')
    end

    it "errors with hash with non-array :value" do
      expect { R509::Cert::Extensions::KeyUsage.new({:value => "string"}) }.to raise_error(ArgumentError, 'You must pass a hash with a key :value that contains an array of strings (see README)')
    end
  end

  context "ExtendedKeyUsage" do
    context "creation & yaml generation" do
      context "single EKU" do
        before :all do
          @args = { :value => ['serverAuth'], :critical => false }
          @eku = R509::Cert::Extensions::ExtendedKeyUsage.new(@args)
        end

        it "creates extension" do
          @eku.allowed_uses.should == ['serverAuth']
        end

        it "builds yaml" do
          YAML.load(@eku.to_yaml).should == @args
        end
      end

      context "multiple EKU" do
        before :all do
          @args = { :value => ['serverAuth','codeSigning'], :critical => false }
          @eku = R509::Cert::Extensions::ExtendedKeyUsage.new(@args)
        end

        it "creates extension" do
          @eku.allowed_uses.should == ['serverAuth','codeSigning']
        end

        it "builds yaml" do
          YAML.load(@eku.to_yaml).should == @args
        end
      end

      context "default criticality" do
        before :all do
          @args = { :value => ['serverAuth'] }
          @eku = R509::Cert::Extensions::ExtendedKeyUsage.new(@args)
        end

        it "creates extension" do
          @eku.critical?.should be_false
        end

        it "builds yaml" do
          YAML.load(@eku.to_yaml).should == @args.merge(:critical => false)
        end
      end

      context "non-default criticality" do
        before :all do
          @args = { :value => ['serverAuth'], :critical => true }
          @eku = R509::Cert::Extensions::ExtendedKeyUsage.new(@args)
        end

        it "creates extension" do
          @eku.critical?.should be_true
        end

        it "builds yaml" do
          YAML.load(@eku.to_yaml).should == @args
        end
      end

    end

    context "with one allowed use" do
      before :all do
        @allowed_uses = [ ExtendedKeyUsage::AU_WEB_SERVER_AUTH ]
        @extension_value = @allowed_uses.join( ", " )
      end

      it_should_behave_like "a correct R509 ExtendedKeyUsage object", false
      it_should_behave_like "a correct R509 ExtendedKeyUsage object", true
    end

    context "with some allowed uses" do
      before :all do
        # this spec and the one below alternate the uses
        @allowed_uses = [ ExtendedKeyUsage::AU_WEB_SERVER_AUTH, ExtendedKeyUsage::AU_CODE_SIGNING ]
        @extension_value = @allowed_uses.join( ", " )
      end

      it_should_behave_like "a correct R509 ExtendedKeyUsage object", false
      it_should_behave_like "a correct R509 ExtendedKeyUsage object", true
    end

    context "with some different allowed uses" do
      before :all do
        @allowed_uses = [ ExtendedKeyUsage::AU_WEB_CLIENT_AUTH, ExtendedKeyUsage::AU_EMAIL_PROTECTION ]
        @extension_value = @allowed_uses.join( ", " )
      end

      it_should_behave_like "a correct R509 ExtendedKeyUsage object", false
      it_should_behave_like "a correct R509 ExtendedKeyUsage object", true
    end

    context "with all allowed uses" do
      before :all do
        @allowed_uses = [
          ExtendedKeyUsage::AU_WEB_SERVER_AUTH,
          ExtendedKeyUsage::AU_CODE_SIGNING,
          ExtendedKeyUsage::AU_WEB_CLIENT_AUTH,
          ExtendedKeyUsage::AU_EMAIL_PROTECTION,
          ExtendedKeyUsage::AU_TIME_STAMPING,
          ExtendedKeyUsage::AU_OCSP_SIGNING,
          ExtendedKeyUsage::AU_ANY_EXTENDED_KEY_USAGE
        ]
        @extension_value = @allowed_uses.join( ", " )
      end

      it_should_behave_like "a correct R509 ExtendedKeyUsage object", false
      it_should_behave_like "a correct R509 ExtendedKeyUsage object", true
    end
  end

end
