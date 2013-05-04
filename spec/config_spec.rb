require 'spec_helper'
require 'r509/config'
require 'r509/exceptions'

describe R509::Config::CAConfigPool do
  context "defined manually" do
    it "has no configs" do
      pool = R509::Config::CAConfigPool.new({})

      pool["first"].should == nil
    end

    it "has one config" do
      config = R509::Config::CAConfig.new(
        :ca_cert => TestFixtures.test_ca_cert,
        :profiles => { "first_profile" => R509::Config::CAProfile.new }
      )

      pool = R509::Config::CAConfigPool.new({
        "first" => config
      })

      pool["first"].should == config
    end
  end

  context "all configs" do
    it "no configs" do
      pool = R509::Config::CAConfigPool.new({})
      pool.all.should == []
    end

    it "one config" do
      config = R509::Config::CAConfig.new(
        :ca_cert => TestFixtures.test_ca_cert,
        :profiles => { "first_profile" => R509::Config::CAProfile.new }
      )

      pool = R509::Config::CAConfigPool.new({
        "first" => config
      })

      pool.all.should == [config]
    end

    it "two configs" do
      config1 = R509::Config::CAConfig.new(
        :ca_cert => TestFixtures.test_ca_cert,
        :profiles => { "first_profile" => R509::Config::CAProfile.new }
      )
      config2 = R509::Config::CAConfig.new(
        :ca_cert => TestFixtures.test_ca_cert,
        :profiles => { "first_profile" => R509::Config::CAProfile.new }
      )

      pool = R509::Config::CAConfigPool.new({
        "first" => config1,
        "second" => config2
      })

      pool.all.size.should == 2
      pool.all.include?(config1).should == true
      pool.all.include?(config2).should == true
    end
  end

  context "loaded from YAML" do
    it "should load two configs" do
      pool = R509::Config::CAConfigPool.from_yaml("certificate_authorities", File.read("#{File.dirname(__FILE__)}/fixtures/config_pool_test_minimal.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"})

      pool.names.should include("test_ca", "second_ca")

      pool["test_ca"].should_not == nil
      pool["test_ca"].num_profiles.should == 0
      pool["second_ca"].should_not == nil
      pool["second_ca"].num_profiles.should == 0
    end
  end
end

describe R509::Config::CAConfig do
  before :each do
    @config = R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert
    )
  end

  subject {@config}

  its(:default_md) {should == "SHA1"}
  its(:allowed_mds) {should be_nil}
  its(:crl_validity_hours) {should == 168}
  its(:ocsp_validity_hours) {should == 168}
  its(:ocsp_start_skew_seconds) {should == 3600}
  its(:cdp_location) {should be_nil}
  its(:ocsp_location) {should be_nil}
  its(:num_profiles) {should == 0}

  it "should have the proper CA cert" do
    @config.ca_cert.to_pem.should == TestFixtures.test_ca_cert.to_pem
  end

  it "should have the proper CA key" do
    @config.ca_cert.key.to_pem.should == TestFixtures.test_ca_cert.key.to_pem
  end

  context "validates data" do
    it "raises an error if you don't pass :ca_cert" do
      expect { R509::Config::CAConfig.new(:crl_validity_hours => 2) }.to raise_error ArgumentError, 'Config object requires that you pass :ca_cert'
    end
    it "raises an error if :ca_cert is not of type R509::Cert" do
      expect { R509::Config::CAConfig.new(:ca_cert => 'not a cert, and not right type') }.to raise_error ArgumentError, ':ca_cert must be of type R509::Cert'
    end
    it "raises an error if :ocsp_cert that is not R509::Cert" do
      expect { R509::Config::CAConfig.new(:ca_cert => TestFixtures.test_ca_cert, :ocsp_cert => "not a cert") }.to raise_error ArgumentError, ':ocsp_cert, if provided, must be of type R509::Cert'
    end
    it "raises an error if :ocsp_cert does not contain a private key" do
      expect { R509::Config::CAConfig.new( :ca_cert => TestFixtures.test_ca_cert, :ocsp_cert => R509::Cert.new( :cert => TestFixtures::TEST_CA_CERT) ) }.to raise_error ArgumentError, ':ocsp_cert must contain a private key, not just a certificate'
    end
    it "raises an error if you pass an ocsp_location that is not an array" do
      expect { R509::Config::CAConfig.new( :ca_cert => TestFixtures.test_ca_cert, :ocsp_location => "some-url" ) }.to raise_error(ArgumentError, 'ocsp_location must be an array if provided')
    end
    it "raises an error if you pass a ca_issuers_location that is not an array" do
      expect { R509::Config::CAConfig.new( :ca_cert => TestFixtures.test_ca_cert, :ca_issuers_location => "some-url" ) }.to raise_error(ArgumentError, 'ca_issuers_location must be an array if provided')
    end
    it "raises an error if you pass a cdp_location that is not an array" do
      expect { R509::Config::CAConfig.new( :ca_cert => TestFixtures.test_ca_cert, :cdp_location => "some-url" ) }.to raise_error(ArgumentError, 'cdp_location must be an array if provided')
    end

    it "errors when supplying invalid default_md" do
      expect { R509::Config::CAConfig.new( :ca_cert => TestFixtures.test_ca_cert, :default_md => "notahash" ) }.to raise_error(ArgumentError, "An unknown message digest was supplied. Permitted: #{R509::MessageDigest::KNOWN_MDS.join(", ")}")
    end

  end

  it "loads allowed_mds and adds default_md when not present" do
    config = R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert,
      :allowed_mds => ['sha256','sha1'],
      :default_md => 'sha384'
    )
    config.allowed_mds.should =~ ['SHA1','SHA256','SHA384']
  end

  it "loads allowed_mds without an explicit default_md" do
    config = R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert,
      :allowed_mds => ['sha256','sha1']
    )
    config.allowed_mds.should =~ ['SHA1','SHA256']
    config.default_md.should == R509::MessageDigest::DEFAULT_MD
  end

  it "loads allowed_mds with an explicit default_md" do
    config = R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert,
      :allowed_mds => ['sha384','sha256'],
      :default_md => "SHA256"
    )
    config.allowed_mds.should =~ ['SHA384','SHA256']
    config.default_md.should == 'SHA256'
  end

  it "loads default_md with no explicit allowed_mds" do
    config = R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert,
      :default_md => "sha256"
    )
    config.allowed_mds.should be_nil
    config.default_md.should == 'SHA256'
  end

  it "loads the config even if :ca_cert does not contain a private key" do
    config = R509::Config::CAConfig.new( :ca_cert => R509::Cert.new( :cert => TestFixtures::TEST_CA_CERT) )
    config.ca_cert.subject.to_s.should_not be_nil
  end
  it "returns the correct cert object on #ocsp_cert if none is specified" do
    @config.ocsp_cert.should == @config.ca_cert
  end
  it "returns the correct cert object on #ocsp_cert if an ocsp_cert was specified" do
    ocsp_cert = R509::Cert.new(
      :cert => TestFixtures::TEST_CA_OCSP_CERT,
      :key => TestFixtures::TEST_CA_OCSP_KEY
    )
    config = R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert,
      :ocsp_cert => ocsp_cert
    )

    config.ocsp_cert.should == ocsp_cert
  end
  it "fails to specify a non-Config::CAProfile as the profile" do
    config = R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert
    )

    expect{ config.set_profile("bogus", "not a Config::CAProfile")}.to raise_error TypeError
  end

  it "shouldn't let you specify a profile that's not a Config::CAProfile, on instantiation" do
    expect{ R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert,
      :profiles => { "first_profile" => "not a Config::CAProfile" }
    ) }.to raise_error TypeError
  end

  it "can specify a single profile" do
    first_profile = R509::Config::CAProfile.new

    config = R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert,
      :profiles => { "first_profile" => first_profile }
    )

    config.profile("first_profile").should == first_profile
  end

  it "raises an error if you specify an invalid profile" do
    first_profile = R509::Config::CAProfile.new

    config = R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert,
      :profiles => { "first_profile" => first_profile }
    )

    expect { config.profile("non-existent-profile") }.to raise_error(R509::R509Error, "unknown profile 'non-existent-profile'")
  end

  it "should load YAML" do
    config = R509::Config::CAConfig.from_yaml("test_ca", File.read("#{File.dirname(__FILE__)}/fixtures/config_test.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"})
    config.crl_validity_hours.should == 72
    config.ocsp_validity_hours.should == 96
    config.default_md.should == "SHA512"
    config.num_profiles.should == 7
    config.profile("ocsp_delegate_with_no_check").ocsp_no_check.should == true
    config.profile("inhibit_policy").inhibit_any_policy.should == 2
    config.profile("policy_constraints").policy_constraints["require_explicit_policy"].should == 1
    config.profile("policy_constraints").policy_constraints["inhibit_policy_mapping"].should == 0
    config.profile("name_constraints").name_constraints.should_not be_nil
  end
  it "loads OCSP cert/key from yaml" do
    config = R509::Config::CAConfig.from_yaml("ocsp_delegate_ca", File.read("#{File.dirname(__FILE__)}/fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"})
    config.ocsp_cert.has_private_key?.should == true
    config.ocsp_cert.subject.to_s.should == "/C=US/ST=Illinois/L=Chicago/O=r509 LLC/CN=r509 OCSP Signer"
  end
  it "loads OCSP pkcs12 from yaml" do
    config = R509::Config::CAConfig.from_yaml("ocsp_pkcs12_ca", File.read("#{File.dirname(__FILE__)}/fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"})
    config.ocsp_cert.has_private_key?.should == true
    config.ocsp_cert.subject.to_s.should == "/C=US/ST=Illinois/L=Chicago/O=r509 LLC/CN=r509 OCSP Signer"
  end
  it "loads OCSP cert/key in engine from yaml" do
    #most of this code path is tested by loading ca_cert engine.
    #look there for the extensive doubling
    expect { R509::Config::CAConfig.from_yaml("ocsp_engine_ca", File.read("#{File.dirname(__FILE__)}/fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"}) }.to raise_error(ArgumentError,"You must supply a key_name with an engine")
  end
  it "loads OCSP chain from yaml" do
    config = R509::Config::CAConfig.from_yaml("ocsp_chain_ca", File.read("#{File.dirname(__FILE__)}/fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"})
    config.ocsp_chain.size.should == 2
    config.ocsp_chain[0].kind_of?(OpenSSL::X509::Certificate).should == true
    config.ocsp_chain[1].kind_of?(OpenSSL::X509::Certificate).should == true
  end
  it "should load subject_item_policy from yaml (if present)" do
    config = R509::Config::CAConfig.from_yaml("test_ca", File.read("#{File.dirname(__FILE__)}/fixtures/config_test.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"})
    config.profile("server").subject_item_policy.should be_nil
    config.profile("server_with_subject_item_policy").subject_item_policy.optional.should include("O","OU")
    config.profile("server_with_subject_item_policy").subject_item_policy.required.should include("CN","ST","C")
  end

  it "should load YAML which only has a CA Cert and Key defined" do
    config = R509::Config::CAConfig.from_yaml("test_ca", File.read("#{File.dirname(__FILE__)}/fixtures/config_test_minimal.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"})
    config.num_profiles.should == 0
  end

  it "should load YAML which has CA cert and key with password" do
    expect { R509::Config::CAConfig.from_yaml("password_ca", File.read("#{File.dirname(__FILE__)}/fixtures/config_test_password.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"}) }.to_not raise_error
  end

  it "should load YAML which has a PKCS12 with password" do
    expect { R509::Config::CAConfig.from_yaml("pkcs12_ca", File.read("#{File.dirname(__FILE__)}/fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"}) }.to_not raise_error
  end

  it "raises error on YAML with pkcs12 and key" do
    expect { R509::Config::CAConfig.from_yaml("pkcs12_key_ca", File.read("#{File.dirname(__FILE__)}/fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"}) }.to raise_error(ArgumentError, "You can't specify both pkcs12 and key")
  end

  it "raises error on YAML with pkcs12 and cert" do
    expect { R509::Config::CAConfig.from_yaml("pkcs12_cert_ca", File.read("#{File.dirname(__FILE__)}/fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"}) }.to raise_error(ArgumentError, "You can't specify both pkcs12 and cert")
  end

  it "raises error on YAML with pkcs12 and engine" do
    expect { R509::Config::CAConfig.from_yaml("pkcs12_engine_ca", File.read("#{File.dirname(__FILE__)}/fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"}) }.to raise_error(ArgumentError, "You can't specify both engine and pkcs12")
  end

  it "loads config with cert and no key (useful in certain cases)" do
    config = R509::Config::CAConfig.from_yaml("cert_no_key_ca", File.read("#{File.dirname(__FILE__)}/fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"})
    config.ca_cert.subject.to_s.should_not be_nil
  end

  it "should load YAML which has an engine" do
    fake_engine = double("fake_engine")
    fake_engine.should_receive(:kind_of?).with(OpenSSL::Engine).and_return(true)
    faux_key = OpenSSL::PKey::RSA.new(TestFixtures::TEST_CA_KEY)
    fake_engine.should_receive(:load_private_key).twice.with("key").and_return(faux_key)
    engine = {"SO_PATH" => "path", "ID" => "id"}

    R509::Engine.instance.should_receive(:load).with(engine).and_return(fake_engine)

    config = R509::Config::CAConfig.load_from_hash({"ca_cert"=>{"cert"=>"#{File.dirname(__FILE__)}/fixtures/test_ca.cer", "engine"=>engine, "key_name" => "key"}, "default_md"=>"SHA512", "profiles"=>{}})
  end

  it "should fail if YAML for ca_cert contains engine and key" do
    expect { R509::Config::CAConfig.from_yaml("engine_and_key", File.read("#{File.dirname(__FILE__)}/fixtures/config_test_engine_key.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"}) }.to raise_error(ArgumentError, "You can't specify both key and engine")
  end

  it "should fail if YAML for ca_cert contains engine but no key_name" do
    expect { R509::Config::CAConfig.from_yaml("engine_no_key_name", File.read("#{File.dirname(__FILE__)}/fixtures/config_test_engine_no_key_name.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"}) }.to raise_error(ArgumentError, 'You must supply a key_name with an engine')
  end

  it "should fail if YAML config is null" do
    expect{ R509::Config::CAConfig.from_yaml("no_config_here", File.read("#{File.dirname(__FILE__)}/fixtures/config_test.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"}) }.to raise_error(ArgumentError)
  end

  it "should fail if YAML config isn't a hash" do
    expect{ R509::Config::CAConfig.from_yaml("config_is_string", File.read("#{File.dirname(__FILE__)}/fixtures/config_test.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"}) }.to raise_error(ArgumentError)
  end

  it "should fail if YAML config doesn't give a root CA directory that's a directory" do
    expect{ R509::Config::CAConfig.from_yaml("test_ca", File.read("#{File.dirname(__FILE__)}/fixtures/config_test.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures/no_directory_here"}) }.to raise_error(R509::R509Error)
  end

  it "should load YAML from filename" do
    config = R509::Config::CAConfig.load_yaml("test_ca", "#{File.dirname(__FILE__)}/fixtures/config_test.yaml", {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"})
    config.crl_validity_hours.should == 72
    config.ocsp_validity_hours.should == 96
    config.default_md.should == "SHA512"
    config.allowed_mds.should =~ ["SHA1","SHA256","SHA512"]
  end

  it "can specify crl_number_file" do
    config = R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert,
      :crl_number_file => "crl_number_file.txt"
    )
    config.crl_number_file.should == 'crl_number_file.txt'
  end

  it "can specify crl_list_file" do
    config = R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert,
      :crl_list_file => "crl_list_file.txt"
    )
    config.crl_list_file.should == 'crl_list_file.txt'
  end

end

describe R509::Config::SubjectItemPolicy do
  it "raises an error if you supply a non-hash" do
    expect { R509::Config::SubjectItemPolicy.new('string') }.to raise_error(ArgumentError, "Must supply a hash in form 'shortname'=>'required/optional'")
  end
  it "raises an error if a required element is missing" do
    subject_item_policy = R509::Config::SubjectItemPolicy.new("CN" => "required", "O" => "required", "OU" => "optional", "L" => "required")
    subject = R509::Subject.new [["CN","langui.sh"],["OU","Org Unit"],["O","Org"]]
    expect { subject_item_policy.validate_subject(subject) }.to raise_error(R509::R509Error, /This profile requires you supply/)
  end
  it "raises an error if your hash values are anything other than required or optional" do
    expect { R509::Config::SubjectItemPolicy.new("CN" => "somethirdoption") }.to raise_error(ArgumentError, "Unknown subject item policy value. Allowed values are required and optional")
  end
  it "validates a subject with the same fields as the policy" do
    subject_item_policy = R509::Config::SubjectItemPolicy.new("CN" => "required", "O" => "required", "OU" => "optional")
    subject = R509::Subject.new [["CN","langui.sh"],["OU","Org Unit"],["O","Org"]]
    validated_subject = subject_item_policy.validate_subject(subject)
    validated_subject.to_s.should == subject.to_s
  end
  it "preserves subject order when applying policies" do
    subject_item_policy = R509::Config::SubjectItemPolicy.new("CN" => "required", "O" => "required", "OU" => "optional", "L" => "required", "C" => "required")
    subject = R509::Subject.new [["C","US"],["L","Chicago"],["ST","Illinois"],["CN","langui.sh"],["OU","Org Unit"],["O","Org"]]
    validated_subject = subject_item_policy.validate_subject(subject)
    validated_subject.to_s.should == "/C=US/L=Chicago/CN=langui.sh/OU=Org Unit/O=Org"
  end
  it "does not match if you get case of subject_item_policy element wrong" do
    subject_item_policy = R509::Config::SubjectItemPolicy.new("cn" => "required")
    subject = R509::Subject.new [["CN","langui.sh"]]
    expect { subject_item_policy.validate_subject(subject) }.to raise_error(R509::R509Error, 'This profile requires you supply cn')
  end
  it "removes subject items that are not in the policy" do
    subject_item_policy = R509::Config::SubjectItemPolicy.new("CN" => "required")
    subject = R509::Subject.new [["CN","langui.sh"],["OU","Org Unit"],["O","Org"]]
    validated_subject = subject_item_policy.validate_subject(subject)
    validated_subject.to_s.should == "/CN=langui.sh"
  end
  it "does not reorder subject items as it validates" do
    subject_item_policy = R509::Config::SubjectItemPolicy.new("CN" => "required", "O" => "required", "OU" => "optional", "L" => "required")
    subject = R509::Subject.new [["L","Chicago"],["CN","langui.sh"],["OU","Org Unit"],["O","Org"]]
    validated_subject = subject_item_policy.validate_subject(subject)
    validated_subject.to_s.should == subject.to_s
  end
  it "loads all the required and optional elements" do
    subject_item_policy = R509::Config::SubjectItemPolicy.new("CN" => "required", "O" => "required", "OU" => "optional", "L" => "required", "emailAddress" => "optional")
    subject_item_policy.optional.should include("OU","emailAddress")
    subject_item_policy.required.should include("CN","O","L")
  end
end

describe R509::Config::CAProfile do
  context "validate certificate policy structure" do
    it "must be an array" do
      expect { R509::Config::CAProfile.new(:certificate_policies => "whatever") }.to raise_error(ArgumentError,'Not a valid certificate policy structure. Must be an array of hashes')
    end
    it "require a policy identifier" do
      expect { R509::Config::CAProfile.new(:certificate_policies => [{"stuff" => "thing"}]) }.to raise_error(ArgumentError,'Each policy requires a policy identifier')
    end
    it "the cps uri must be array of strings" do
      expect { R509::Config::CAProfile.new(:certificate_policies => [{"policy_identifier" => "1.2.3.4.5", "cps_uris" => "not an array"}]) }.to raise_error(ArgumentError,'CPS URIs must be an array of strings')
    end
    it "user notices must be an array of hashes" do
      expect { R509::Config::CAProfile.new(:certificate_policies => [{"policy_identifier" => "1.2.3.4.5", "user_notices" => "not an array"}]) }.to raise_error(ArgumentError,'User notices must be an array of hashes')
    end
    it "org in user notice requires notice numbers" do
      expect { R509::Config::CAProfile.new(:certificate_policies => [{"policy_identifier" => "1.2.3.4.5", "user_notices" => [{"explicit_text" => "explicit", "organization" => "something"}]}]) }.to raise_error(ArgumentError,'If you provide an organization you must provide notice numbers')
    end
    it "notice numbers in user notice requires org" do
      expect { R509::Config::CAProfile.new(:certificate_policies => [{"policy_identifier" => "1.2.3.4.5", "user_notices" => [{"explicit_text" => "explicit", "notice_numbers" => "1,2,3"}]}]) }.to raise_error(ArgumentError,'If you provide notice numbers you must provide an organization')
    end
  end
  context "validate basic constraints structure" do
    it "must be a hash with key \"ca\"" do
      expect { R509::Config::CAProfile.new(:basic_constraints => 'string') }.to raise_error(ArgumentError, "You must supply a hash with a key named \"ca\" with a boolean value")
      expect { R509::Config::CAProfile.new(:basic_constraints => {}) }.to raise_error(ArgumentError, "You must supply a hash with a key named \"ca\" with a boolean value")
    end
    it "must have true or false for the ca key value" do
      expect { R509::Config::CAProfile.new(:basic_constraints => {"ca" => 'truestring'}) }.to raise_error(ArgumentError, "You must supply true/false for the ca key when specifying basic constraints")
    end
    it "must not pass a path_length if ca is false" do
      expect { R509::Config::CAProfile.new(:basic_constraints => {"ca" => false, "path_length" => 5}) }.to raise_error(ArgumentError, "path_length is not allowed when ca is false")
    end
    it "must pass a non-negative integer to path_length" do
      expect { R509::Config::CAProfile.new(:basic_constraints => {"ca" => true, "path_length" => -1.5}) }.to raise_error(ArgumentError, "Path length must be a non-negative integer (>= 0)")
      expect { R509::Config::CAProfile.new(:basic_constraints => {"ca" => true, "path_length" => 1.5}) }.to raise_error(ArgumentError, "Path length must be a non-negative integer (>= 0)")
    end
    it "does not require a path_length when ca is true" do
      ca_profile = R509::Config::CAProfile.new(:basic_constraints => {"ca" => true})
      ca_profile.basic_constraints.should == {"ca" => true }
    end
    it "allows ca:false" do
      ca_profile = R509::Config::CAProfile.new(:basic_constraints => {"ca" => false})
      ca_profile.basic_constraints.should == {"ca" => false }
    end
    it "allows ca:true and a valid path length" do
      ca_profile = R509::Config::CAProfile.new(:basic_constraints => {"ca" => true, "path_length" => 2})
      ca_profile.basic_constraints.should == {"ca" => true, "path_length" => 2 }
    end
  end
  context "validate key usage" do
    it "errors with non-array" do
      expect { R509::Config::CAProfile.new( :key_usage => 'not an array' ) }.to raise_error(ArgumentError, 'key_usage must be an array of strings (see README)')
    end
    it "loads properly" do
      ku = ['digitalSignature']
      profile = R509::Config::CAProfile.new( :key_usage => ku )
      profile.key_usage.should == ku
    end
  end
  context "validate extended key usage" do
    it "errors with non-array" do
      expect { R509::Config::CAProfile.new( :extended_key_usage => 'not an array' ) }.to raise_error(ArgumentError, 'extended_key_usage must be an array of strings (see README)')
    end
    it "loads properly" do
      eku = ['serverAuth']
      profile = R509::Config::CAProfile.new( :extended_key_usage => eku )
      profile.extended_key_usage.should == eku
    end
  end
  context "validate subject item policy" do
    it "raises an error with an invalid subject_item_policy" do
      expect { R509::Config::CAProfile.new( :subject_item_policy => "lenient!" ) }.to raise_error(ArgumentError,'subject_item_policy must be of type R509::Config::SubjectItemPolicy')
    end
    it "stores a valid subject_item_policy" do
      policy = R509::Config::SubjectItemPolicy.new("CN" => "required")
      expect { R509::Config::CAProfile.new( :subject_item_policy => policy) }.to_not raise_error
    end
  end
  context "validate inhibit any policy" do
    it "raises an error when not a number" do
      expect { R509::Config::CAProfile.new( :inhibit_any_policy => "string" ) }.to raise_error(ArgumentError,'Inhibit any policy must be a non-negative integer')
    end
    it "raises an error when not >= 0" do
      expect { R509::Config::CAProfile.new( :inhibit_any_policy => -5 ) }.to raise_error(ArgumentError,'Inhibit any policy must be a non-negative integer')
    end
    it "loads when providing valid data" do
      profile = R509::Config::CAProfile.new(:inhibit_any_policy => 3)
      profile.inhibit_any_policy.should == 3
    end
  end
  context "validate policy constraints" do
    it "raises an error when not a hash" do
      expect { R509::Config::CAProfile.new( :policy_constraints => "string" ) }.to raise_error(ArgumentError,'Policy constraints must be provided as a hash with at least one of the two allowed keys: "inhibit_policy_mapping" and "require_explicit_policy"')
    end
    it "raises an error when no keys" do
      expect { R509::Config::CAProfile.new( :policy_constraints => {} ) }.to raise_error(ArgumentError,'Policy constraints must have at least one of two keys: "inhibit_policy_mapping" and "require_explicit_policy" and the value must be non-negative')
    end
    it "raises an error when inhibit_policy_mapping is not valid" do
      expect { R509::Config::CAProfile.new( :policy_constraints => {"inhibit_policy_mapping" => -5} ) }.to raise_error(ArgumentError,'inhibit_policy_mapping must be a non-negative integer')
    end
    it "raises an error when require_explicit_policy is not valid" do
      expect { R509::Config::CAProfile.new( :policy_constraints => {"require_explicit_policy" => -1} ) }.to raise_error(ArgumentError,'require_explicit_policy must be a non-negative integer')
    end
    it "loads when provided inhibit_policy_mapping" do
      profile = R509::Config::CAProfile.new( :policy_constraints => {"require_explicit_policy" => 1} )
      profile.policy_constraints["require_explicit_policy"].should == 1
    end
    it "loads when provided require_explicit_policy" do
      profile = R509::Config::CAProfile.new( :policy_constraints => {"inhibit_policy_mapping" => 0} )
      profile.policy_constraints["inhibit_policy_mapping"].should == 0
    end
    it "loads when provided values for both keys" do
      profile = R509::Config::CAProfile.new( :policy_constraints => {"require_explicit_policy" => 1, "inhibit_policy_mapping" => 4} )
      profile.policy_constraints["require_explicit_policy"].should == 1
      profile.policy_constraints["inhibit_policy_mapping"].should == 4
    end
  end
  context "validate name constraints"do
    it "raises an error when not a hash" do
      expect { R509::Config::CAProfile.new( :name_constraints => 'a string' ) }.to raise_error(ArgumentError,'name_constraints must be provided as a hash')
    end
    it "raises an error when permitted and excluded are empty" do
      expect { R509::Config::CAProfile.new( :name_constraints => {"permitted" => [], "excluded" => []} ) }.to raise_error(ArgumentError,'If name_constraints are supplied you must have at least one valid permitted or excluded element')
    end
    it "raises an error when permitted or excluded are not arrays" do
      expect { R509::Config::CAProfile.new( :name_constraints => {"permitted" => 'string', "excluded" => 'string'} ) }.to raise_error(ArgumentError,'permitted must be an array')
    end
    it "raises an error when permitted or excluded elements are not hashes with the required values" do
      expect { R509::Config::CAProfile.new( :name_constraints => {"permitted" => [{"type" => 'DNS'}]} ) }.to raise_error(ArgumentError,'Elements within the permitted array must be hashes with both type and value')
      expect { R509::Config::CAProfile.new( :name_constraints => {"permitted" => [{'value' => '127'}]} ) }.to raise_error(ArgumentError,'Elements within the permitted array must be hashes with both type and value')
    end
    it "raises an error when an invalid type is specified" do
      expect { R509::Config::CAProfile.new( :name_constraints => {"permitted" => [{'type' => 'invalid', 'value' => '127'}]} ) }.to raise_error(ArgumentError,'invalid is not an allowed type. Check R509::ASN1::GeneralName.map_type_to_tag to see a list of types')
    end
    it "loads a config with just permitted" do
      profile = R509::Config::CAProfile.new(:name_constraints => {"permitted" => [ { 'type' => 'DNS', 'value' => 'domain.com' } ] } )
      profile.name_constraints["permitted"][0]['type'] = 'DNS'
      profile.name_constraints["permitted"][0]['value'] = 'domain.com'
    end
    it "loads a config with just excluded" do
      profile = R509::Config::CAProfile.new(:name_constraints => {"excluded" => [ { 'type' => 'IP', 'value' => '127.0.0.1/255.255.255.255' } ] } )
      profile.name_constraints["excluded"][0]['type'] = 'IP'
      profile.name_constraints["excluded"][0]['value'] = '127.0.0.1/255.255.255.255'
    end
    it "loads a config with both permitted and excluded" do
      profile = R509::Config::CAProfile.new(:name_constraints => {"permitted" => [ { 'type' => 'DNS', 'value' => 'domain.com' } ], "excluded" => [ { 'type' => 'IP', 'value' => '127.0.0.1/255.255.255.255' } ] } )
      profile.name_constraints["permitted"][0]['type'] = 'DNS'
      profile.name_constraints["permitted"][0]['value'] = 'domain.com'
      profile.name_constraints["excluded"][0]['type'] = 'IP'
      profile.name_constraints["excluded"][0]['value'] = '127.0.0.1/255.255.255.255'
    end
  end
  it "initializes and stores the options provided" do
    profile = R509::Config::CAProfile.new(
      :basic_constraints => {"ca" => true},
      :key_usage => ["digitalSignature"],
      :extended_key_usage => ["serverAuth"],
      :certificate_policies => [
          { "policy_identifier" => "2.16.840.1.12345.1.2.3.4.1",
  "cps_uris" => ["http://example.com/cps","http://other.com/cps"],
  "user_notices" => [ {"explicit_text" => "thing", "organization" => "my org", "notice_numbers" => "1,2,3,4"} ]
          }
      ],
      :ocsp_no_check => true
    )
    profile.basic_constraints.should == {"ca" => true}
    profile.key_usage.should == ["digitalSignature"]
    profile.extended_key_usage.should == ["serverAuth"]
    profile.certificate_policies[0]["policy_identifier"].should == "2.16.840.1.12345.1.2.3.4.1"
    profile.ocsp_no_check.should == true
  end
  it "initializes with expected defaults" do
    profile = R509::Config::CAProfile.new
    profile.basic_constraints.should == nil
    profile.key_usage.should == nil
    profile.extended_key_usage.should == nil
    profile.certificate_policies.should == nil
    profile.ocsp_no_check.should == false
    profile.subject_item_policy.should == nil
  end
  it "loads profiles from YAML while setting expected defaults" do
    config = R509::Config::CAConfig.from_yaml("test_ca", File.read("#{File.dirname(__FILE__)}/fixtures/config_test.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"})
    server_profile = config.profile("server") # no ocsp_no_check node
    server_profile.ocsp_no_check.should == false
    ocsp_profile = config.profile("ocsp_delegate_with_no_check") # ocsp_no_check => true
    ocsp_profile.ocsp_no_check.should == true
    client_profile = config.profile("client") # ocsp_no_check => false
    client_profile.ocsp_no_check.should == false
  end
end
