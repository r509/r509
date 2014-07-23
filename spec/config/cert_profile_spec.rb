require 'spec_helper'
require 'r509/config/cert_profile'
require 'r509/config/ca_config'
require 'r509/exceptions'

describe R509::Config::CertProfile do
  context "validates allowed_mds and default_md" do
    it "loads allowed_mds and adds default_md when not present" do
      profile = R509::Config::CertProfile.new(
        :allowed_mds => ['sha256', 'sha1'],
        :default_md => 'sha384'
      )
      expect(profile.allowed_mds).to match_array(['SHA1', 'SHA256', 'SHA384'])
    end

    it "loads allowed_mds without an explicit default_md" do
      profile = R509::Config::CertProfile.new(
        :allowed_mds => ['sha256', 'sha1']
      )
      expect(profile.allowed_mds).to match_array(['SHA1', 'SHA256'])
      expect(profile.default_md).to eq(R509::MessageDigest::DEFAULT_MD)
    end

    it "loads allowed_mds with an explicit default_md" do
      profile = R509::Config::CertProfile.new(
        :allowed_mds => ['sha384', 'sha256'],
        :default_md => "SHA256"
      )
      expect(profile.allowed_mds).to match_array(['SHA384', 'SHA256'])
      expect(profile.default_md).to eq('SHA256')
    end

    it "loads default_md with no explicit allowed_mds" do
      profile = R509::Config::CertProfile.new(
        :default_md => "sha256"
      )
      expect(profile.allowed_mds).to be_nil
      expect(profile.default_md).to eq('SHA256')
    end

    it "errors when supplying invalid default_md" do
      expect { R509::Config::CertProfile.new(:default_md => "notahash") }.to raise_error(ArgumentError, "An unknown message digest was supplied. Permitted: #{R509::MessageDigest::KNOWN_MDS.join(", ")}")
    end

    it "errors when supplying invalid subject item policy" do
      expect { R509::Config::CertProfile.new(:subject_item_policy => "notapolicy") }.to raise_error(ArgumentError, 'subject_item_policy must be of type R509::Config::SubjectItemPolicy')
    end
  end
  it "initializes with expected defaults" do
    profile = R509::Config::CertProfile.new
    expect(profile.basic_constraints).to be_nil
    expect(profile.key_usage).to be_nil
    expect(profile.extended_key_usage).to be_nil
    expect(profile.certificate_policies).to be_nil
    expect(profile.inhibit_any_policy).to be_nil
    expect(profile.policy_constraints).to be_nil
    expect(profile.name_constraints).to be_nil
    expect(profile.ocsp_no_check).to be_nil
    expect(profile.authority_info_access).to be_nil
    expect(profile.crl_distribution_points).to be_nil
    expect(profile.allowed_mds).to be_nil
    expect(profile.default_md).to eq(R509::MessageDigest::DEFAULT_MD)
    expect(profile.subject_item_policy).to be_nil
  end
  it "loads profiles from YAML while setting expected defaults" do
    config = R509::Config::CAConfig.from_yaml("test_ca", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test.yaml"), :ca_root_path => "#{File.dirname(__FILE__)}/../fixtures")
    server_profile = config.profile("server") # no ocsp_no_check node
    expect(server_profile.ocsp_no_check).to be_nil
    ocsp_profile = config.profile("ocsp_delegate_with_no_check") # ocsp_no_check => true
    expect(ocsp_profile.ocsp_no_check).not_to be_nil
    client_profile = config.profile("client") # ocsp_no_check => false
    expect(client_profile.ocsp_no_check).to be_nil
  end

  it "builds YAML" do
    config = R509::Config::CAConfig.from_yaml("test_ca", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test.yaml"), :ca_root_path => "#{File.dirname(__FILE__)}/../fixtures")
    expect(YAML.load(config.profile("server").to_yaml)).to eq({ "basic_constraints" => { :ca => false, :critical => true }, "key_usage" => { :value => ["digitalSignature", "keyEncipherment"], :critical => false }, "extended_key_usage" => { :value => ["serverAuth"], :critical => false }, "default_md" => R509::MessageDigest::DEFAULT_MD })
  end

  it "includes crl distribution points in the yaml" do
    config = R509::Config::CertProfile.new(
      :crl_distribution_points => R509::Cert::Extensions::CRLDistributionPoints.new(
        :value => [{ :type => 'URI', :value => 'http://crl.myca.net/ca.crl' }]
      )
    )
    expect(YAML.load(config.to_yaml)).to eq({ "crl_distribution_points" => { :critical => false, :value => [{ :type => "URI", :value => "http://crl.myca.net/ca.crl" }] }, "default_md" => "SHA1" })
  end
end
