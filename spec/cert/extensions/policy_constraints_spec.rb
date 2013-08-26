require 'spec_helper'

include R509::Cert::Extensions

shared_examples_for "a correct R509 PolicyConstraints object" do |critical|
  before :all do
    extension_name = "policyConstraints"
    klass = PolicyConstraints
    ef = OpenSSL::X509::ExtensionFactory.new
    openssl_ext = ef.create_extension( extension_name, @extension_value, critical)
    @r509_ext = klass.new( openssl_ext )
  end

  it "should have the expected require policy" do
    @r509_ext.require_explicit_policy.should == @require_explicit_policy
  end
  it "should have the expected inhibit mapping" do
    @r509_ext.inhibit_policy_mapping.should == @inhibit_policy_mapping
  end
end

describe R509::Cert::Extensions::PolicyConstraints do
  include R509::Cert::Extensions

  context "validate policy constraints" do
    it "raises an error when not a hash" do
      expect { R509::Cert::Extensions::PolicyConstraints.new( "string" ) }.to raise_error(ArgumentError,'Policy constraints must be provided as a hash with at least one of the two allowed keys: :inhibit_policy_mapping and :require_explicit_policy')
    end

    it "raises an error when no keys" do
      expect { R509::Cert::Extensions::PolicyConstraints.new( {} ) }.to raise_error(ArgumentError,'Policy constraints must have at least one of two keys: :inhibit_policy_mapping and :require_explicit_policy and the value must be non-negative')
    end

    it "raises an error when inhibit_policy_mapping is not valid" do
      expect { R509::Cert::Extensions::PolicyConstraints.new( :inhibit_policy_mapping => -5 ) }.to raise_error(ArgumentError,'inhibit_policy_mapping must be a non-negative integer')
    end

    it "raises an error when require_explicit_policy is not valid" do
      expect { R509::Cert::Extensions::PolicyConstraints.new( :require_explicit_policy => -1 ) }.to raise_error(ArgumentError,'require_explicit_policy must be a non-negative integer')
    end
  end

  context "PolicyConstraints" do
    context "creation & yaml generation" do
      context "creates with require explicit policy" do
        before :all do
          @args = { :require_explicit_policy => 1, :critical => true }
          @pc = R509::Cert::Extensions::PolicyConstraints.new(@args)
        end

        it "creates extension" do
          @pc.require_explicit_policy.should == 1
        end

        it "builds yaml" do
          YAML.load(@pc.to_yaml).should == @args
        end
      end

      context "creates with inhibit policy mapping" do
        before :all do
          @args = { :inhibit_policy_mapping => 1, :critical => true }
          @pc = R509::Cert::Extensions::PolicyConstraints.new(@args)
        end

        it "creates extension" do
          @pc.inhibit_policy_mapping.should == 1
        end

        it "builds yaml" do
          YAML.load(@pc.to_yaml).should == @args
        end
      end

      context "creates with both" do
        before :all do
          @args = {
            :inhibit_policy_mapping => 1,
            :require_explicit_policy => 3,
            :critical => true
          }
          @pc = R509::Cert::Extensions::PolicyConstraints.new(@args)
        end

        it "creates extension" do
          @pc.inhibit_policy_mapping.should == 1
          @pc.require_explicit_policy.should == 3
        end

        it "builds yaml" do
          YAML.load(@pc.to_yaml).should == @args
        end
      end

      context "default criticality" do
        before :all do
          @args = { :inhibit_policy_mapping => 1 }
          @pc = R509::Cert::Extensions::PolicyConstraints.new(@args)
        end

        it "creates extension" do
          @pc.critical?.should == true
        end

        it "builds yaml" do
          YAML.load(@pc.to_yaml).should == @args.merge(:critical => true)
        end
      end

      context "non-default criticality" do
        before :all do
          @args = { :inhibit_policy_mapping => 1, :critical => false }
          @pc = R509::Cert::Extensions::PolicyConstraints.new(@args)
        end

        it "creates extension" do
          @pc.critical?.should == false
        end

        it "builds yaml" do
          YAML.load(@pc.to_yaml).should == @args
        end
      end

    end
    context "with just require" do
      before :all do
        @require_explicit_policy = 2
        @inhibit_policy_mapping = nil
        @extension_value = "requireExplicitPolicy:#{@require_explicit_policy}"
      end
      it_should_behave_like "a correct R509 PolicyConstraints object", false
      it_should_behave_like "a correct R509 PolicyConstraints object", true
    end
    context "with just inhibit" do
      before :all do
        @require_explicit_policy = nil
        @inhibit_policy_mapping = 3
        @extension_value = "inhibitPolicyMapping:#{@inhibit_policy_mapping}"
      end
      it_should_behave_like "a correct R509 PolicyConstraints object", false
      it_should_behave_like "a correct R509 PolicyConstraints object", true
    end
    context "with both require and inhibit" do
      before :all do
        @require_explicit_policy = 2
        @inhibit_policy_mapping = 3
        @extension_value = "requireExplicitPolicy:#{@require_explicit_policy},inhibitPolicyMapping:#{@inhibit_policy_mapping}"
      end
      it_should_behave_like "a correct R509 PolicyConstraints object", false
      it_should_behave_like "a correct R509 PolicyConstraints object", true
    end

  end
end
