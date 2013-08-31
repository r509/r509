require 'spec_helper'
require 'r509/config/cert_profile'
require 'r509/config/ca_config'
require 'r509/exceptions'

describe R509::Config::CertProfile do
  context "validates allowed_mds and default_md" do
    it "loads allowed_mds and adds default_md when not present" do
      profile = R509::Config::CertProfile.new(
        :allowed_mds => ['sha256','sha1'],
        :default_md => 'sha384'
      )
      profile.allowed_mds.should =~ ['SHA1','SHA256','SHA384']
    end

    it "loads allowed_mds without an explicit default_md" do
      profile = R509::Config::CertProfile.new(
        :allowed_mds => ['sha256','sha1']
      )
      profile.allowed_mds.should =~ ['SHA1','SHA256']
      profile.default_md.should == R509::MessageDigest::DEFAULT_MD
    end

    it "loads allowed_mds with an explicit default_md" do
      profile = R509::Config::CertProfile.new(
        :allowed_mds => ['sha384','sha256'],
        :default_md => "SHA256"
      )
      profile.allowed_mds.should =~ ['SHA384','SHA256']
      profile.default_md.should == 'SHA256'
    end

    it "loads default_md with no explicit allowed_mds" do
      profile = R509::Config::CertProfile.new(
        :default_md => "sha256"
      )
      profile.allowed_mds.should be_nil
      profile.default_md.should == 'SHA256'
    end

    it "errors when supplying invalid default_md" do
      expect { R509::Config::CertProfile.new( :default_md => "notahash" ) }.to raise_error(ArgumentError, "An unknown message digest was supplied. Permitted: #{R509::MessageDigest::KNOWN_MDS.join(", ")}")
    end

    it "errors when supplying invalid subject item policy" do
      expect { R509::Config::CertProfile.new( :subject_item_policy => "notapolicy") }.to raise_error(ArgumentError, 'subject_item_policy must be of type R509::Config::SubjectItemPolicy')
    end
  end
  it "initializes with expected defaults" do
    profile = R509::Config::CertProfile.new
    profile.basic_constraints.should == nil
    profile.key_usage.should == nil
    profile.extended_key_usage.should == nil
    profile.certificate_policies.should == nil
    profile.inhibit_any_policy.should == nil
    profile.policy_constraints.should == nil
    profile.name_constraints.should == nil
    profile.ocsp_no_check.should == nil
    profile.authority_info_access.should == nil
    profile.crl_distribution_points.should == nil
    profile.allowed_mds.should == nil
    profile.default_md.should == R509::MessageDigest::DEFAULT_MD
    profile.subject_item_policy.should == nil
  end
  it "loads profiles from YAML while setting expected defaults" do
    config = R509::Config::CAConfig.from_yaml("test_ca", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/../fixtures"})
    server_profile = config.profile("server") # no ocsp_no_check node
    server_profile.ocsp_no_check.should == nil
    ocsp_profile = config.profile("ocsp_delegate_with_no_check") # ocsp_no_check => true
    ocsp_profile.ocsp_no_check.should_not == nil
    client_profile = config.profile("client") # ocsp_no_check => false
    client_profile.ocsp_no_check.should == nil
  end

  it "builds YAML" do
    config = R509::Config::CAConfig.from_yaml("test_ca", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/../fixtures"})
    YAML.load(config.profile("server").to_yaml).should == {"basic_constraints"=>{:ca=>false, :critical=>true}, "key_usage"=>{:value=>["digitalSignature", "keyEncipherment"], :critical=>false}, "extended_key_usage"=>{:value=>["serverAuth"], :critical=>false}, "default_md"=>R509::MessageDigest::DEFAULT_MD}
  end
end
