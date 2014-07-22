require 'spec_helper'

shared_examples_for "a correct R509 BasicConstraints object" do |critical|
  before :all do
    extension_name = "basicConstraints"
    klass = R509::Cert::Extensions::BasicConstraints
    ef = OpenSSL::X509::ExtensionFactory.new
    openssl_ext = ef.create_extension(extension_name, @extension_value, critical)
    @r509_ext = klass.new(openssl_ext)
  end

  it "is_ca? should correctly report whether it's a CA certificate (critical:#{critical})" do
    @r509_ext.is_ca?.should == @is_ca
  end

  it "the path length should be correct (critical:#{critical})" do
    @r509_ext.path_length.should == @pathlen
  end

  it "allows_sub_ca? should correctly report whether its path length allows it to issue CA certs (critical:#{critical})" do
    @r509_ext.allows_sub_ca?.should == @allows_sub_ca
  end

  it "reports #critical? properly" do
    @r509_ext.critical?.should == critical
  end
end

describe R509::Cert::Extensions::BasicConstraints do

  context "validate basic constraints structure" do
    it "must be a hash with key :ca" do
      expect { R509::Cert::Extensions::BasicConstraints.new('string') }.to raise_error(ArgumentError, "You must supply a hash with a key named :ca with a boolean value")
      expect { R509::Cert::Extensions::BasicConstraints.new({}) }.to raise_error(ArgumentError, "You must supply a hash with a key named :ca with a boolean value")
    end
    it "must have true or false for the ca key value" do
      expect { R509::Cert::Extensions::BasicConstraints.new(:ca => 'truestring') }.to raise_error(ArgumentError, "You must supply true/false for the :ca key when specifying basic constraints")
    end
    it "must not pass a path_length if ca is false" do
      expect { R509::Cert::Extensions::BasicConstraints.new(:ca => false, :path_length => 5) }.to raise_error(ArgumentError, ":path_length is not allowed when :ca is false")
    end
    it "must pass a non-negative integer to path_length" do
      expect { R509::Cert::Extensions::BasicConstraints.new(:ca => true, :path_length => -1.5) }.to raise_error(ArgumentError, "Path length must be a positive integer (>= 0)")
      expect { R509::Cert::Extensions::BasicConstraints.new(:ca => true, :path_length => 1.5) }.to raise_error(ArgumentError, "Path length must be a positive integer (>= 0)")
    end
  end

  context "BasicConstraints" do
    context "creation & yaml generation" do
      context "CA:true without pathlen" do

        before :all do
          @args = { :ca => true, :critical => true }
          @bc = R509::Cert::Extensions::BasicConstraints.new(@args)
        end

        it "creates extension" do
          @bc.is_ca?.should be_true
          @bc.path_length.should be_nil
        end

        it "builds yaml" do
          YAML.load(@bc.to_yaml).should == @args
        end
      end

      context "CA:TRUE with path_length" do
        before :all do
          @args = { :ca => true, :path_length => 3, :critical => true }
          @bc = R509::Cert::Extensions::BasicConstraints.new(@args)
        end

        it "creates extension" do
          @bc.is_ca?.should be_true
          @bc.path_length.should == 3
        end

        it "builds yaml" do
          YAML.load(@bc.to_yaml).should == @args
        end
      end

      context "CA:FALSE" do
        before :all do
          @args = { :ca => false, :critical => true }
          @bc = R509::Cert::Extensions::BasicConstraints.new(@args)
        end

        it "creates extension" do
          @bc.is_ca?.should be_false
          @bc.path_length.should be_nil
        end

        it "builds yaml" do
          YAML.load(@bc.to_yaml).should == @args
        end
      end

      context "default criticality" do
        before :all do
          @args = { :ca => false }
          @bc = R509::Cert::Extensions::BasicConstraints.new(@args)
        end

        it "creates extension" do
          @bc.critical?.should be_true
        end

        it "builds yaml" do
          YAML.load(@bc.to_yaml).should == @args.merge(:critical => true)
        end
      end

      context "non-default criticality" do
        before :all do
          @args = { :ca => false, :critical => false }
          @bc = R509::Cert::Extensions::BasicConstraints.new(@args)
        end

        it "creates extension" do
          @bc.critical?.should be_false
        end

        it "builds yaml" do
          YAML.load(@bc.to_yaml).should == @args
        end
      end

      it "errors when supplying path_length if CA:FALSE" do
        expect do
          R509::Cert::Extensions::BasicConstraints.new(:ca => false, :path_length => 4)
        end.to raise_error(ArgumentError, ":path_length is not allowed when :ca is false")
      end

    end

    context "with constraints for a CA certificate" do
      before :all do
        @extension_value = "CA:TRUE,pathlen:3"
        @is_ca = true
        @pathlen = 3
        @allows_sub_ca = true
      end

      it_should_behave_like "a correct R509 BasicConstraints object", false
      it_should_behave_like "a correct R509 BasicConstraints object", true
    end

    context "with constraints for a CA certificate with no path length" do
      before :all do
        @extension_value = "CA:TRUE"
        @is_ca = true
        @pathlen = nil
        @allows_sub_ca = true
      end

      it_should_behave_like "a correct R509 BasicConstraints object", false
      it_should_behave_like "a correct R509 BasicConstraints object", true
    end

    context "with constraints for a sub-CA certificate" do
      before :all do
        @extension_value = "CA:TRUE,pathlen:0"
        @is_ca = true
        @pathlen = 0
        @allows_sub_ca = false
      end

      it_should_behave_like "a correct R509 BasicConstraints object", false
      it_should_behave_like "a correct R509 BasicConstraints object", true
    end

    context "with constraints for a non-CA certificate" do
      before :all do
        @extension_value = "CA:FALSE"
        @is_ca = false
        @pathlen = nil
        @allows_sub_ca = false
      end

      it_should_behave_like "a correct R509 BasicConstraints object", false
      it_should_behave_like "a correct R509 BasicConstraints object", true
    end
  end
end
