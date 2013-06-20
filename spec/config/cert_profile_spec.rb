require 'spec_helper'
require 'r509/config/cert_profile'
require 'r509/config/ca_config'
require 'r509/exceptions'

describe R509::Config::CertProfile do
  context "validate certificate policy structure" do
    it "must be an array" do
      expect { R509::Config::CertProfile.new(:certificate_policies => "whatever") }.to raise_error(ArgumentError,'Not a valid certificate policy structure. Must be an array of hashes')
    end
    it "require a policy identifier" do
      expect { R509::Config::CertProfile.new(:certificate_policies => [{"stuff" => "thing"}]) }.to raise_error(ArgumentError,'Each policy requires a policy identifier')
    end
    it "the cps uri must be array of strings" do
      expect { R509::Config::CertProfile.new(:certificate_policies => [{:policy_identifier => "1.2.3.4.5", :cps_uris => "not an array"}]) }.to raise_error(ArgumentError,'CPS URIs must be an array of strings')
    end
    it "user notices must be an array of hashes" do
      expect { R509::Config::CertProfile.new(:certificate_policies => [{:policy_identifier => "1.2.3.4.5", :user_notices => "not an array"}]) }.to raise_error(ArgumentError,'User notices must be an array of hashes')
    end
    it "org in user notice requires notice numbers" do
      expect { R509::Config::CertProfile.new(:certificate_policies => [{:policy_identifier => "1.2.3.4.5", :user_notices => [{:explicit_text => "explicit", :organization => "something"}]}]) }.to raise_error(ArgumentError,'If you provide an organization you must provide notice numbers')
    end
    it "notice numbers in user notice requires org" do
      expect { R509::Config::CertProfile.new(:certificate_policies => [{:policy_identifier => "1.2.3.4.5", :user_notices => [{:explicit_text => "explicit", :notice_numbers => "1,2,3"}]}]) }.to raise_error(ArgumentError,'If you provide notice numbers you must provide an organization')
    end
  end
  context "validate basic constraints structure" do
    it "must be a hash with key \"ca\"" do
      expect { R509::Config::CertProfile.new(:basic_constraints => 'string') }.to raise_error(ArgumentError, "You must supply a hash with a key named :ca with a boolean value")
      expect { R509::Config::CertProfile.new(:basic_constraints => {}) }.to raise_error(ArgumentError, "You must supply a hash with a key named :ca with a boolean value")
    end
    it "must have true or false for the ca key value" do
      expect { R509::Config::CertProfile.new(:basic_constraints => {:ca => 'truestring'}) }.to raise_error(ArgumentError, "You must supply true/false for the :ca key when specifying basic constraints")
    end
    it "must not pass a path_length if ca is false" do
      expect { R509::Config::CertProfile.new(:basic_constraints => {:ca => false, :path_length => 5}) }.to raise_error(ArgumentError, ":path_length is not allowed when :ca is false")
    end
    it "must pass a non-negative integer to path_length" do
      expect { R509::Config::CertProfile.new(:basic_constraints => {:ca => true, :path_length => -1.5}) }.to raise_error(ArgumentError, "Path length must be a non-negative integer (>= 0)")
      expect { R509::Config::CertProfile.new(:basic_constraints => {:ca => true, :path_length => 1.5}) }.to raise_error(ArgumentError, "Path length must be a non-negative integer (>= 0)")
    end
    it "does not require a path_length when ca is true" do
      ca_profile = R509::Config::CertProfile.new(:basic_constraints => {:ca => true})
      ca_profile.basic_constraints.should == {:ca => true }
    end
    it "allows ca:false" do
      ca_profile = R509::Config::CertProfile.new(:basic_constraints => {:ca => false})
      ca_profile.basic_constraints.should == {:ca => false }
    end
    it "allows ca:true and a valid path length" do
      ca_profile = R509::Config::CertProfile.new(:basic_constraints => {:ca => true, :path_length => 2})
      ca_profile.basic_constraints.should == {:ca => true, :path_length => 2 }
    end
  end
  context "validate key usage" do
    it "errors with non-array" do
      expect { R509::Config::CertProfile.new( :key_usage => 'not an array' ) }.to raise_error(ArgumentError, 'key_usage must be an array of strings (see README)')
    end
    it "loads properly" do
      ku = ['digitalSignature']
      profile = R509::Config::CertProfile.new( :key_usage => ku )
      profile.key_usage.should == ku
    end
  end
  context "validate extended key usage" do
    it "errors with non-array" do
      expect { R509::Config::CertProfile.new( :extended_key_usage => 'not an array' ) }.to raise_error(ArgumentError, 'extended_key_usage must be an array of strings (see README)')
    end
    it "loads properly" do
      eku = ['serverAuth']
      profile = R509::Config::CertProfile.new( :extended_key_usage => eku )
      profile.extended_key_usage.should == eku
    end
  end
  context "validate subject item policy" do
    it "raises an error with an invalid subject_item_policy" do
      expect { R509::Config::CertProfile.new( :subject_item_policy => "lenient!" ) }.to raise_error(ArgumentError,'subject_item_policy must be of type R509::Config::SubjectItemPolicy')
    end
    it "stores a valid subject_item_policy" do
      policy = R509::Config::SubjectItemPolicy.new("CN" => {:policy => "required"})
      expect { R509::Config::CertProfile.new( :subject_item_policy => policy) }.to_not raise_error
    end
  end
  context "validate inhibit any policy" do
    it "raises an error when not a number" do
      expect { R509::Config::CertProfile.new( :inhibit_any_policy => "string" ) }.to raise_error(ArgumentError,'Inhibit any policy must be a non-negative integer')
    end
    it "raises an error when not >= 0" do
      expect { R509::Config::CertProfile.new( :inhibit_any_policy => -5 ) }.to raise_error(ArgumentError,'Inhibit any policy must be a non-negative integer')
    end
    it "loads when providing valid data" do
      profile = R509::Config::CertProfile.new(:inhibit_any_policy => 3)
      profile.inhibit_any_policy.should == 3
    end
  end
  context "validate policy constraints" do
    it "raises an error when not a hash" do
      expect { R509::Config::CertProfile.new( :policy_constraints => "string" ) }.to raise_error(ArgumentError,'Policy constraints must be provided as a hash with at least one of the two allowed keys: :inhibit_policy_mapping and :require_explicit_policy')
    end
    it "raises an error when no keys" do
      expect { R509::Config::CertProfile.new( :policy_constraints => {} ) }.to raise_error(ArgumentError,'Policy constraints must have at least one of two keys: :inhibit_policy_mapping and :require_explicit_policy and the value must be non-negative')
    end
    it "raises an error when inhibit_policy_mapping is not valid" do
      expect { R509::Config::CertProfile.new( :policy_constraints => {:inhibit_policy_mapping => -5} ) }.to raise_error(ArgumentError,'inhibit_policy_mapping must be a non-negative integer')
    end
    it "raises an error when require_explicit_policy is not valid" do
      expect { R509::Config::CertProfile.new( :policy_constraints => {:require_explicit_policy => -1} ) }.to raise_error(ArgumentError,'require_explicit_policy must be a non-negative integer')
    end
    it "loads when provided inhibit_policy_mapping" do
      profile = R509::Config::CertProfile.new( :policy_constraints => {:require_explicit_policy => 1} )
      profile.policy_constraints[:require_explicit_policy].should == 1
    end
    it "loads when provided require_explicit_policy" do
      profile = R509::Config::CertProfile.new( :policy_constraints => {:inhibit_policy_mapping => 0} )
      profile.policy_constraints[:inhibit_policy_mapping].should == 0
    end
    it "loads when provided values for both keys" do
      profile = R509::Config::CertProfile.new( :policy_constraints => {:require_explicit_policy => 1, :inhibit_policy_mapping => 4} )
      profile.policy_constraints[:require_explicit_policy].should == 1
      profile.policy_constraints[:inhibit_policy_mapping].should == 4
    end
  end
  context "validate name constraints"do
    it "raises an error when not a hash" do
      expect { R509::Config::CertProfile.new( :name_constraints => 'a string' ) }.to raise_error(ArgumentError,'name_constraints must be provided as a hash')
    end
    it "raises an error when permitted and excluded are empty" do
      expect { R509::Config::CertProfile.new( :name_constraints => {:permitted => [], :excluded => []} ) }.to raise_error(ArgumentError,'If name_constraints are supplied you must have at least one valid :permitted or :excluded element')
    end
    it "raises an error when permitted or excluded are not arrays" do
      expect { R509::Config::CertProfile.new( :name_constraints => {:permitted => 'string', :excluded => 'string'} ) }.to raise_error(ArgumentError,'permitted must be an array')
    end
    it "raises an error when permitted or excluded elements are not hashes with the required values" do
      expect { R509::Config::CertProfile.new( :name_constraints => {:permitted => [{"type" => 'DNS'}]} ) }.to raise_error(ArgumentError,'Elements within the permitted array must be hashes with both type and value')
      expect { R509::Config::CertProfile.new( :name_constraints => {:permitted => [{'value' => '127'}]} ) }.to raise_error(ArgumentError,'Elements within the permitted array must be hashes with both type and value')
    end
    it "raises an error when an invalid type is specified" do
      expect { R509::Config::CertProfile.new( :name_constraints => {:permitted => [{:type => 'invalid', :value => '127'}]} ) }.to raise_error(ArgumentError,'invalid is not an allowed type. Check R509::ASN1::GeneralName.map_type_to_tag to see a list of types')
    end
    it "loads a config with just permitted" do
      profile = R509::Config::CertProfile.new(:name_constraints => {:permitted => [ { :type => 'DNS', :value => 'domain.com' } ] } )
      profile.name_constraints[:permitted][0][:type] = 'DNS'
      profile.name_constraints[:permitted][0][:value] = 'domain.com'
    end
    it "loads a config with just excluded" do
      profile = R509::Config::CertProfile.new(:name_constraints => {:excluded => [ { :type => 'IP', :value => '127.0.0.1/255.255.255.255' } ] } )
      profile.name_constraints[:excluded][0][:type] = 'IP'
      profile.name_constraints[:excluded][0][:value] = '127.0.0.1/255.255.255.255'
    end
    it "loads a config with both permitted and excluded" do
      profile = R509::Config::CertProfile.new(:name_constraints => {:permitted => [ { :type => 'DNS', :value => 'domain.com' } ], :excluded => [ { :type => 'IP', :value => '127.0.0.1/255.255.255.255' } ] } )
      profile.name_constraints[:permitted][0][:type] = 'DNS'
      profile.name_constraints[:permitted][0][:value] = 'domain.com'
      profile.name_constraints[:excluded][0][:type] = 'IP'
      profile.name_constraints[:excluded][0][:value] = '127.0.0.1/255.255.255.255'
    end
  end

  it "raises an error if you pass an ocsp_location that is not an array" do
    expect { R509::Config::CertProfile.new( :ocsp_location => "some-url" ) }.to raise_error(ArgumentError, 'ocsp_location must be an array or R509::ASN1::GeneralNames object if provided')
  end
  it "raises an error if you pass a ca_issuers_location that is not an array" do
    expect { R509::Config::CertProfile.new( :ca_issuers_location => "some-url" ) }.to raise_error(ArgumentError, 'ca_issuers_location must be an array or R509::ASN1::GeneralNames object if provided')
  end
  it "raises an error if you pass a cdp_location that is not an array" do
    expect { R509::Config::CertProfile.new( :cdp_location => "some-url" ) }.to raise_error(ArgumentError, 'cdp_location must be an array or R509::ASN1::GeneralNames object if provided')
  end

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
  end
  it "initializes and stores the options provided" do
    profile = R509::Config::CertProfile.new(
      :basic_constraints => {:ca => true},
      :key_usage => ["digitalSignature"],
      :extended_key_usage => ["serverAuth"],
      :certificate_policies => [
          { :policy_identifier => "2.16.840.1.12345.1.2.3.4.1",
  :cps_uris => ["http://example.com/cps","http://other.com/cps"],
  :user_notices => [ {:explicit_text => "thing", :organization => "my org", :notice_numbers => "1,2,3,4"} ]
          }
      ],
      :ocsp_no_check => true
    )
    profile.basic_constraints.should == {:ca => true}
    profile.key_usage.should == ["digitalSignature"]
    profile.extended_key_usage.should == ["serverAuth"]
    profile.certificate_policies[0][:policy_identifier].should == "2.16.840.1.12345.1.2.3.4.1"
    profile.ocsp_no_check.should == true
  end
  it "initializes with expected defaults" do
    profile = R509::Config::CertProfile.new
    profile.basic_constraints.should == nil
    profile.key_usage.should == nil
    profile.extended_key_usage.should == nil
    profile.certificate_policies.should == nil
    profile.ocsp_no_check.should == false
    profile.subject_item_policy.should == nil
  end
  it "loads profiles from YAML while setting expected defaults" do
    config = R509::Config::CAConfig.from_yaml("test_ca", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/../fixtures"})
    server_profile = config.profile("server") # no ocsp_no_check node
    server_profile.ocsp_no_check.should == false
    ocsp_profile = config.profile("ocsp_delegate_with_no_check") # ocsp_no_check => true
    ocsp_profile.ocsp_no_check.should == true
    client_profile = config.profile("client") # ocsp_no_check => false
    client_profile.ocsp_no_check.should == false
  end
end
