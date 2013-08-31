require 'spec_helper'
require 'r509/config/ca_config'
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
        :profiles => { "first_profile" => R509::Config::CertProfile.new }
      )

      pool = R509::Config::CAConfigPool.new({
        "first" => config
      })

      pool["first"].should == config
    end
  end

  context "all configs" do
    context "no configs" do
      before :all do
        @pool = R509::Config::CAConfigPool.new({})
      end

      it "creates" do
        @pool.all.should == []
      end

      it "builds yaml" do
        YAML.load(@pool.to_yaml).should == {}
      end
    end

    context "one config" do
      before :all do
        @config = R509::Config::CAConfig.new(
          :ca_cert => TestFixtures.test_ca_cert,
          :profiles => { "first_profile" => R509::Config::CertProfile.new }
        )
        @pool = R509::Config::CAConfigPool.new({
          "first" => @config
        })
      end

      it "creates" do
        @pool.all.should == [@config]
      end

      it "builds yaml" do
        YAML.load(@pool.to_yaml).should == {"first"=>{"ca_cert"=>{"cert"=>"<add_path>", "key"=>"<add_path>"}, "ocsp_start_skew_seconds"=>3600, "ocsp_validity_hours"=>168, "crl_start_skew_seconds"=>3600, "crl_validity_hours"=>168, "crl_md"=>"SHA1", "profiles"=>{"first_profile"=>{"default_md"=>"SHA1"}}}}
      end
    end

    context "two configs" do
      before :all do
        @config1 = R509::Config::CAConfig.new(
          :ca_cert => TestFixtures.test_ca_cert,
          :profiles => { "first_profile" => R509::Config::CertProfile.new }
        )
        @config2 = R509::Config::CAConfig.new(
          :ca_cert => TestFixtures.test_ca_cert,
          :profiles => { "first_profile" => R509::Config::CertProfile.new }
        )
        @pool = R509::Config::CAConfigPool.new({
          "first" => @config1,
          "second" => @config2
        })
      end

      it "creates" do
        @pool.all.size.should == 2
        @pool.all.include?(@config1).should == true
        @pool.all.include?(@config2).should == true
      end

      it "builds yaml" do
        YAML.load(@pool.to_yaml).should == {"first"=>{"ca_cert"=>{"cert"=>"<add_path>", "key"=>"<add_path>"}, "ocsp_start_skew_seconds"=>3600, "ocsp_validity_hours"=>168, "crl_start_skew_seconds"=>3600, "crl_validity_hours"=>168, "crl_md"=>"SHA1", "profiles"=>{"first_profile"=>{"default_md"=>"SHA1"}}}, "second"=>{"ca_cert"=>{"cert"=>"<add_path>", "key"=>"<add_path>"}, "ocsp_start_skew_seconds"=>3600, "ocsp_validity_hours"=>168, "crl_start_skew_seconds"=>3600, "crl_validity_hours"=>168, "crl_md"=>"SHA1", "profiles"=>{"first_profile"=>{"default_md"=>"SHA1"}}}}
      end
    end
  end

  context "loaded from YAML" do
    it "should load two configs" do
      pool = R509::Config::CAConfigPool.from_yaml("certificate_authorities", File.read("#{File.dirname(__FILE__)}/../fixtures/config_pool_test_minimal.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/../fixtures"})

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

  its(:crl_validity_hours) {should == 168}
  its(:ocsp_validity_hours) {should == 168}
  its(:ocsp_start_skew_seconds) {should == 3600}
  its(:num_profiles) {should == 0}

  it "should have the proper CA cert" do
    @config.ca_cert.to_pem.should == TestFixtures.test_ca_cert.to_pem
  end

  it "should have the proper CA key" do
    @config.ca_cert.key.to_pem.should == TestFixtures.test_ca_cert.key.to_pem
  end

  context "to_yaml" do
    it "includes engine stub if in hardware" do
      config = R509::Config::CAConfig.new(:ca_cert => TestFixtures.test_ca_cert)
      config.ca_cert.key.should_receive(:in_hardware?).and_return(true)
      YAML.load(config.to_yaml).should == {"ca_cert"=>{"cert"=>"<add_path>", "engine"=>{:so_path=>"<add_path>", :id=>"<add_name>"}}, "ocsp_start_skew_seconds"=>3600, "ocsp_validity_hours"=>168, "crl_start_skew_seconds"=>3600, "crl_validity_hours"=>168, "crl_md"=>"SHA1"}
    end
    it "includes ocsp_cert stub if not nil" do
      config = R509::Config::CAConfig.new(:ca_cert => TestFixtures.test_ca_cert, :ocsp_cert => TestFixtures.test_ca_cert)
      YAML.load(config.to_yaml).should ==  {"ca_cert"=>{"cert"=>"<add_path>", "key"=>"<add_path>"}, "ocsp_cert"=>{"cert"=>"<add_path>", "key"=>"<add_path>"}, "ocsp_start_skew_seconds"=>3600, "ocsp_validity_hours"=>168, "crl_start_skew_seconds"=>3600, "crl_validity_hours"=>168, "crl_md"=>"SHA1"}
    end
    it "includes crl_cert stub if not nil" do
      config = R509::Config::CAConfig.new(:ca_cert => TestFixtures.test_ca_cert, :crl_cert => TestFixtures.test_ca_cert)
      YAML.load(config.to_yaml).should ==  {"ca_cert"=>{"cert"=>"<add_path>", "key"=>"<add_path>"}, "crl_cert"=>{"cert"=>"<add_path>", "key"=>"<add_path>"}, "ocsp_start_skew_seconds"=>3600, "ocsp_validity_hours"=>168, "crl_start_skew_seconds"=>3600, "crl_validity_hours"=>168, "crl_md"=>"SHA1"}
    end
    it "includes ocsp_chain if not nil" do
      config = R509::Config::CAConfig.new(:ca_cert => TestFixtures.test_ca_cert, :ocsp_chain => [OpenSSL::X509::Certificate.new])
      YAML.load(config.to_yaml).should == {"ca_cert"=>{"cert"=>"<add_path>", "key"=>"<add_path>"}, "ocsp_chain"=>"<add_path>", "ocsp_start_skew_seconds"=>3600, "ocsp_validity_hours"=>168, "crl_start_skew_seconds"=>3600, "crl_validity_hours"=>168, "crl_md"=>"SHA1"}
    end
    it "includes crl_list_file if not nil" do
      config = R509::Config::CAConfig.new(:ca_cert => TestFixtures.test_ca_cert, :crl_list_file => '/some/path')
      YAML.load(config.to_yaml).should == {"ca_cert"=>{"cert"=>"<add_path>", "key"=>"<add_path>"}, "ocsp_start_skew_seconds"=>3600, "ocsp_validity_hours"=>168, "crl_start_skew_seconds"=>3600, "crl_validity_hours"=>168, "crl_list_file"=>"/some/path", "crl_md"=>"SHA1"}
    end
    it "includes crl_number_file if not nil" do
      config = R509::Config::CAConfig.new(:ca_cert => TestFixtures.test_ca_cert, :crl_number_file => '/some/path')
      YAML.load(config.to_yaml).should == {"ca_cert"=>{"cert"=>"<add_path>", "key"=>"<add_path>"}, "ocsp_start_skew_seconds"=>3600, "ocsp_validity_hours"=>168, "crl_start_skew_seconds"=>3600, "crl_validity_hours"=>168, "crl_number_file"=>"/some/path", "crl_md"=>"SHA1"}
    end
    it "includes profiles" do
      config = R509::Config::CAConfig.new(:ca_cert => TestFixtures.test_ca_cert)
      profile = R509::Config::CertProfile.new(
        :basic_constraints => {:ca => true}
      )
      config.set_profile("subroot",profile)
      config.set_profile("subroot_also",profile)
      YAML.load(config.to_yaml).should == {"ca_cert"=>{"cert"=>"<add_path>", "key"=>"<add_path>"}, "ocsp_start_skew_seconds"=>3600, "ocsp_validity_hours"=>168, "crl_start_skew_seconds"=>3600, "crl_validity_hours"=>168, "crl_md"=>"SHA1", "profiles"=>{"subroot"=>{"basic_constraints"=>{:ca=>true, :critical=>true}, "default_md"=>"SHA1"}, "subroot_also"=>{"basic_constraints"=>{:ca=>true, :critical=>true}, "default_md"=>"SHA1"}}}
    end
    it "includes defaults" do
      config = R509::Config::CAConfig.new(:ca_cert => TestFixtures.test_ca_cert)
      YAML.load(config.to_yaml).should == {"ca_cert"=>{"cert"=>"<add_path>", "key"=>"<add_path>"}, "ocsp_start_skew_seconds"=>3600, "ocsp_validity_hours"=>168, "crl_start_skew_seconds"=>3600, "crl_validity_hours"=>168, "crl_md"=>"SHA1"}
    end
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
    it "raises an error if :crl_cert that is not R509::Cert" do
      expect { R509::Config::CAConfig.new(:ca_cert => TestFixtures.test_ca_cert, :crl_cert => "not a cert") }.to raise_error ArgumentError, ':crl_cert, if provided, must be of type R509::Cert'
    end
    it "raises an error if :crl_cert does not contain a private key" do
      expect { R509::Config::CAConfig.new( :ca_cert => TestFixtures.test_ca_cert, :crl_cert => R509::Cert.new( :cert => TestFixtures::TEST_CA_CERT) ) }.to raise_error ArgumentError, ':crl_cert must contain a private key, not just a certificate'
    end
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
  it "returns the correct cert object on #crl_cert if none is specified" do
    @config.crl_cert.should == @config.ca_cert
  end
  it "returns the correct cert object on #crl_cert if an crl_cert was specified" do
    crl_cert = R509::Cert.new(
      :cert => TestFixtures::TEST_CA_OCSP_CERT,
      :key => TestFixtures::TEST_CA_OCSP_KEY
    )
    config = R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert,
      :crl_cert => crl_cert
    )

    config.crl_cert.should == crl_cert
  end
  it "fails to specify a non-Config::CertProfile as the profile" do
    config = R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert
    )

    expect{ config.set_profile("bogus", "not a Config::CertProfile")}.to raise_error TypeError
  end

  it "shouldn't let you specify a profile that's not a Config::CertProfile, on instantiation" do
    expect{ R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert,
      :profiles => { "first_profile" => "not a Config::CertProfile" }
    ) }.to raise_error TypeError
  end

  it "can specify a single profile" do
    first_profile = R509::Config::CertProfile.new

    config = R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert,
      :profiles => { "first_profile" => first_profile }
    )

    config.profile("first_profile").should == first_profile
  end

  it "raises an error if you specify an invalid profile" do
    first_profile = R509::Config::CertProfile.new

    config = R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert,
      :profiles => { "first_profile" => first_profile }
    )

    expect { config.profile("non-existent-profile") }.to raise_error(R509::R509Error, "unknown profile 'non-existent-profile'")
  end

  it "should load YAML" do
    config = R509::Config::CAConfig.from_yaml("test_ca", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/../fixtures"})
    config.crl_validity_hours.should == 72
    config.ocsp_validity_hours.should == 96
    config.num_profiles.should == 9
    config.profile("mds").default_md.should == "SHA512"
    config.profile("mds").allowed_mds.should == ['SHA512','SHA1']
    aia = config.profile("aia_cdp").authority_info_access
    aia.ocsp.uris.should == ['http://ocsp.domain.com']
    aia.ca_issuers.uris.should == ['http://www.domain.com/cert.cer']
    cdp = config.profile("aia_cdp").crl_distribution_points
    cdp.uris.should == ['http://crl.domain.com/something.crl']
    config.profile("ocsp_delegate_with_no_check").ocsp_no_check.should_not be_nil
    config.profile("inhibit_policy").inhibit_any_policy.value.should == 2
    config.profile("policy_constraints").policy_constraints.require_explicit_policy.should == 1
    config.profile("policy_constraints").policy_constraints.inhibit_policy_mapping.should == 0
    config.profile("name_constraints").name_constraints.should_not be_nil
  end
  it "loads CRL cert/key from yaml" do
    config = R509::Config::CAConfig.from_yaml("crl_delegate_ca", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/../fixtures"})
    config.crl_cert.has_private_key?.should == true
    config.crl_cert.subject.to_s.should == "/C=US/ST=Illinois/L=Chicago/O=r509 LLC/CN=r509 CRL Delegate"
  end
  it "loads CRL pkcs12 from yaml" do
    config = R509::Config::CAConfig.from_yaml("crl_pkcs12_ca", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/../fixtures"})
    config.crl_cert.has_private_key?.should == true
    config.crl_cert.subject.to_s.should == "/C=US/ST=Illinois/L=Chicago/O=r509 LLC/CN=r509 CRL Delegate"
  end
  it "loads CRL cert/key in engine from yaml" do
    expect { R509::Config::CAConfig.from_yaml("crl_engine_ca", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/../fixtures"}) }.to raise_error(ArgumentError,"You must supply a key_name with an engine")
  end
  it "loads OCSP cert/key from yaml" do
    config = R509::Config::CAConfig.from_yaml("ocsp_delegate_ca", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/../fixtures"})
    config.ocsp_cert.has_private_key?.should == true
    config.ocsp_cert.subject.to_s.should == "/C=US/ST=Illinois/L=Chicago/O=r509 LLC/CN=r509 OCSP Signer"
  end
  it "loads OCSP pkcs12 from yaml" do
    config = R509::Config::CAConfig.from_yaml("ocsp_pkcs12_ca", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/../fixtures"})
    config.ocsp_cert.has_private_key?.should == true
    config.ocsp_cert.subject.to_s.should == "/C=US/ST=Illinois/L=Chicago/O=r509 LLC/CN=r509 OCSP Signer"
  end
  it "loads OCSP cert/key in engine from yaml" do
    #most of this code path is tested by loading ca_cert engine.
    expect { R509::Config::CAConfig.from_yaml("ocsp_engine_ca", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/../fixtures"}) }.to raise_error(ArgumentError,"You must supply a key_name with an engine")
  end
  it "loads OCSP chain from yaml" do
    config = R509::Config::CAConfig.from_yaml("ocsp_chain_ca", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/../fixtures"})
    config.ocsp_chain.size.should == 2
    config.ocsp_chain[0].kind_of?(OpenSSL::X509::Certificate).should == true
    config.ocsp_chain[1].kind_of?(OpenSSL::X509::Certificate).should == true
  end
  it "should load subject_item_policy from yaml (if present)" do
    config = R509::Config::CAConfig.from_yaml("test_ca", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/../fixtures"})
    config.profile("server").subject_item_policy.should be_nil
    config.profile("server_with_subject_item_policy").subject_item_policy.optional.should include("O","OU")
    config.profile("server_with_subject_item_policy").subject_item_policy.required.should include("CN","ST","C")
  end

  it "should load YAML which only has a CA Cert and Key defined" do
    config = R509::Config::CAConfig.from_yaml("test_ca", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test_minimal.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/../fixtures"})
    config.num_profiles.should == 0
  end

  it "should load YAML which has CA cert and key with password" do
    expect { R509::Config::CAConfig.from_yaml("password_ca", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test_password.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/../fixtures"}) }.to_not raise_error
  end

  it "should load YAML which has a PKCS12 with password" do
    expect { R509::Config::CAConfig.from_yaml("pkcs12_ca", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/../fixtures"}) }.to_not raise_error
  end

  it "raises error on YAML with pkcs12 and key" do
    expect { R509::Config::CAConfig.from_yaml("pkcs12_key_ca", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/../fixtures"}) }.to raise_error(ArgumentError, "You can't specify both pkcs12 and key")
  end

  it "raises error on YAML with pkcs12 and cert" do
    expect { R509::Config::CAConfig.from_yaml("pkcs12_cert_ca", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/../fixtures"}) }.to raise_error(ArgumentError, "You can't specify both pkcs12 and cert")
  end

  it "raises error on YAML with pkcs12 and engine" do
    expect { R509::Config::CAConfig.from_yaml("pkcs12_engine_ca", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/../fixtures"}) }.to raise_error(ArgumentError, "You can't specify both engine and pkcs12")
  end

  it "loads config with cert and no key (useful in certain cases)" do
    config = R509::Config::CAConfig.from_yaml("cert_no_key_ca", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/../fixtures"})
    config.ca_cert.subject.to_s.should_not be_nil
  end

  it "should load YAML which has an engine" do
    fake_engine = double("fake_engine")
    fake_engine.should_receive(:kind_of?).with(OpenSSL::Engine).and_return(true)
    faux_key = OpenSSL::PKey::RSA.new(TestFixtures::TEST_CA_KEY)
    fake_engine.should_receive(:load_private_key).twice.with("key").and_return(faux_key)
    engine = {"SO_PATH" => "path", "ID" => "id"}

    R509::Engine.instance.should_receive(:load).with(engine).and_return(fake_engine)

    R509::Config::CAConfig.load_from_hash({"ca_cert"=>{"cert"=>"#{File.dirname(__FILE__)}/../fixtures/test_ca.cer", "engine"=>engine, "key_name" => "key"}, "default_md"=>"SHA512", "profiles"=>{}})
  end

  it "should fail if YAML for ca_cert contains engine and key" do
    expect { R509::Config::CAConfig.from_yaml("engine_and_key", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test_engine_key.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/../fixtures"}) }.to raise_error(ArgumentError, "You can't specify both key and engine")
  end

  it "should fail if YAML for ca_cert contains engine but no key_name" do
    expect { R509::Config::CAConfig.from_yaml("engine_no_key_name", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test_engine_no_key_name.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/../fixtures"}) }.to raise_error(ArgumentError, 'You must supply a key_name with an engine')
  end

  it "should fail if YAML config is null" do
    expect{ R509::Config::CAConfig.from_yaml("no_config_here", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/../fixtures"}) }.to raise_error(ArgumentError)
  end

  it "should fail if YAML config isn't a hash" do
    expect{ R509::Config::CAConfig.from_yaml("config_is_string", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/../fixtures"}) }.to raise_error(ArgumentError)
  end

  it "should fail if YAML config doesn't give a root CA directory that's a directory" do
    expect{ R509::Config::CAConfig.from_yaml("test_ca", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/../fixtures/no_directory_here"}) }.to raise_error(R509::R509Error)
  end

  it "should load YAML from filename" do
    config = R509::Config::CAConfig.load_yaml("test_ca", "#{File.dirname(__FILE__)}/../fixtures/config_test.yaml", {:ca_root_path => "#{File.dirname(__FILE__)}/../fixtures"})
    config.crl_validity_hours.should == 72
    config.ocsp_validity_hours.should == 96
    config.num_profiles.should == 9
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
