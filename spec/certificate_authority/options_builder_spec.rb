require 'spec_helper'
require 'r509/config'

describe R509::CertificateAuthority::OptionsBuilder do

  it "errors when the object passed is not a CAConfig" do
    expect { R509::CertificateAuthority::OptionsBuilder.new("string") }.to raise_error(ArgumentError,"You must supply a R509::Config::CAConfig object to this class at instantiation")
  end

  context "enforces subject item policies" do
    before :all do
      config = R509::Config::CAConfig.new( :ca_cert => R509::Cert.new( :cert => TestFixtures::TEST_CA_CERT) )
      subject_item_policy = R509::Config::SubjectItemPolicy.new("CN" => { :policy => "required" } , "O" => { :policy => "required" }, "OU" => { :policy => "optional" }, "L" => { :policy => "required" })
      profile = R509::Config::CertProfile.new(
        :default_md => "SHA512",
        :subject_item_policy => subject_item_policy
      )
      config.set_profile("profile",profile)
      @builder = R509::CertificateAuthority::OptionsBuilder.new(config)
    end
    it "removes disallowed and keeps required/optional items" do
      csr = R509::CSR.new(:subject => [['C','US'],['ST','Illinois'],['L','Chicago'],['O','Paul Kehrer'],['OU','Enginerding'],['CN','langui.sh']], :bit_strength => 1024)
      data = @builder.build_and_enforce(:csr => csr, :profile_name => 'profile')
      data[:subject].to_s.should == '/L=Chicago/O=Paul Kehrer/OU=Enginerding/CN=langui.sh'
    end

    it "raises error when required item is missing" do
      csr = R509::CSR.new(:subject => [['ST','Illinois'],['L','Chicago'],['O','Paul Kehrer']], :bit_strength => 1024)
      expect { @builder.build_and_enforce(:csr => csr, :profile_name => 'profile') }.to raise_error(R509::R509Error, /This profile requires you supply/)
    end
  end

  it "raises error on invalid signature" do
    config = R509::Config::CAConfig.new( :ca_cert => R509::Cert.new( :cert => TestFixtures::TEST_CA_CERT) )
    profile = R509::Config::CertProfile.new(
      :default_md => "SHA512"
    )
    config.set_profile("profile",profile)
    builder = R509::CertificateAuthority::OptionsBuilder.new(config)
    csr = R509::CSR.new(:csr => TestFixtures::CSR_INVALID_SIGNATURE)
    expect { builder.build_and_enforce(:csr => csr, :profile_name => 'profile') }.to raise_error(R509::R509Error, 'Request signature is invalid.')
    spki = R509::SPKI.new(:spki => TestFixtures::SPKI_INVALID_SIGNATURE)
    expect { builder.build_and_enforce(:spki => spki, :profile_name => 'profile') }.to raise_error(R509::R509Error, 'Request signature is invalid.')
  end

  context "extension builder" do
    before :all do
      @config = R509::Config::CAConfig.new( :ca_cert => R509::Cert.new( :cert => TestFixtures::TEST_CA_CERT) )
      @csr = R509::CSR.new(:csr => TestFixtures::CSR)
    end

    it "adds basic constraints" do
      profile = R509::Config::CertProfile.new(
        :basic_constraints => { :ca => false }
      )
      @config.set_profile("profile",profile)
      builder = R509::CertificateAuthority::OptionsBuilder.new(@config)
      data = builder.build_and_enforce(:csr => @csr, :profile_name => 'profile')
      ext = data[:extensions].select{ |el| el.kind_of?(R509::Cert::Extensions::BasicConstraints) }
      ext.size.should == 1
      ext[0].is_ca?.should be_false
    end

    it "creates subject key identifier" do
      profile = R509::Config::CertProfile.new
      @config.set_profile("profile",profile)
      builder = R509::CertificateAuthority::OptionsBuilder.new(@config)
      data = builder.build_and_enforce(:csr => @csr, :profile_name => 'profile')
      data[:extensions].select{ |el| el.kind_of?(R509::Cert::Extensions::SubjectKeyIdentifier) }.size.should == 1
    end

    it "creates authority key identifier" do
      profile = R509::Config::CertProfile.new
      @config.set_profile("profile",profile)
      builder = R509::CertificateAuthority::OptionsBuilder.new(@config)
      data = builder.build_and_enforce(:csr => @csr, :profile_name => 'profile')
      data[:extensions].select{ |el| el.kind_of?(R509::Cert::Extensions::AuthorityKeyIdentifier) }.size.should == 1
    end

    it "adds key usage" do
      profile = R509::Config::CertProfile.new(
        :key_usage => { :value => ['keyEncipherment'] }
      )
      @config.set_profile("profile",profile)
      builder = R509::CertificateAuthority::OptionsBuilder.new(@config)
      data = builder.build_and_enforce(:csr => @csr, :profile_name => 'profile')
      ext = data[:extensions].select{ |el| el.kind_of?(R509::Cert::Extensions::KeyUsage) }
      ext.size.should == 1
      ext[0].allowed_uses.should == ['keyEncipherment']
    end

    it "adds extended key usage" do
      profile = R509::Config::CertProfile.new(
        :extended_key_usage => { :value => ['serverAuth'] }
      )
      @config.set_profile("profile",profile)
      builder = R509::CertificateAuthority::OptionsBuilder.new(@config)
      data = builder.build_and_enforce(:csr => @csr, :profile_name => 'profile')
      ext = data[:extensions].select{ |el| el.kind_of?(R509::Cert::Extensions::ExtendedKeyUsage) }
      ext.size.should == 1
      ext[0].allowed_uses.should == ['serverAuth']
    end

    it "adds certificate policies" do
      profile = R509::Config::CertProfile.new(
        :certificate_policies => { :value => [{ :policy_identifier => "2.16.840.1.99999.21.234" }] }
      )
      @config.set_profile("profile",profile)
      builder = R509::CertificateAuthority::OptionsBuilder.new(@config)
      data = builder.build_and_enforce(:csr => @csr, :profile_name => 'profile')
      data[:extensions].select{ |el| el.kind_of?(R509::Cert::Extensions::CertificatePolicies) }.size.should == 1
    end

    it "adds CRL distribution points" do
      cdp = R509::Cert::Extensions::CRLDistributionPoints.new(:value => [{ :type => 'URI', :value => 'http://crl.domain.com/crl.crl' }])
      profile = R509::Config::CertProfile.new(
        :crl_distribution_points => cdp
      )
      @config.set_profile("profile",profile)
      builder = R509::CertificateAuthority::OptionsBuilder.new(@config)
      data = builder.build_and_enforce(:csr => @csr, :profile_name => 'profile')
      data[:extensions].select{ |el| el.kind_of?(R509::Cert::Extensions::CRLDistributionPoints) }.size.should == 1
    end

    it "adds authority info access" do
      args = { :ca_issuers_location => [{ :type => 'URI', :value => 'http://www.domain.com' }], :ocsp_location => [{ :type => 'URI', :value => 'http://ocsp.domain.com' }], :critical => false }
      aia = R509::Cert::Extensions::AuthorityInfoAccess.new(args)
      profile = R509::Config::CertProfile.new(
        :authority_info_access => aia
      )
      @config.set_profile("profile",profile)
      builder = R509::CertificateAuthority::OptionsBuilder.new(@config)
      data = builder.build_and_enforce(:csr => @csr, :profile_name => 'profile')
      data[:extensions].select{ |el| el.kind_of?(R509::Cert::Extensions::AuthorityInfoAccess) }.size.should == 1
    end

    it "adds inhibit any policy" do
      profile = R509::Config::CertProfile.new(
        :inhibit_any_policy => { :value => 1 }
      )
      @config.set_profile("profile",profile)
      builder = R509::CertificateAuthority::OptionsBuilder.new(@config)
      data = builder.build_and_enforce(:csr => @csr, :profile_name => 'profile')
      data[:extensions].select{ |el| el.kind_of?(R509::Cert::Extensions::InhibitAnyPolicy) }.size.should == 1
    end

    it "adds policy constraints" do
      profile = R509::Config::CertProfile.new(
        :policy_constraints => { :inhibit_policy_mapping => 1 }
      )
      @config.set_profile("profile",profile)
      builder = R509::CertificateAuthority::OptionsBuilder.new(@config)
      data = builder.build_and_enforce(:csr => @csr, :profile_name => 'profile')
      data[:extensions].select{ |el| el.kind_of?(R509::Cert::Extensions::PolicyConstraints) }.size.should == 1
    end

    it "adds name constraints" do
      profile = R509::Config::CertProfile.new(
        :name_constraints => { :permitted => [{ :type => "URI", :value => "domain.com" }] }
      )
      @config.set_profile("profile",profile)
      builder = R509::CertificateAuthority::OptionsBuilder.new(@config)
      data = builder.build_and_enforce(:csr => @csr, :profile_name => 'profile')
      data[:extensions].select{ |el| el.kind_of?(R509::Cert::Extensions::NameConstraints) }.size.should == 1
    end

    it "adds OCSP no check" do
      profile = R509::Config::CertProfile.new(
        :ocsp_no_check => { :value => true }
      )
      @config.set_profile("profile",profile)
      builder = R509::CertificateAuthority::OptionsBuilder.new(@config)
      data = builder.build_and_enforce(:csr => @csr, :profile_name => 'profile')
      data[:extensions].select{ |el| el.kind_of?(R509::Cert::Extensions::OCSPNoCheck) }.size.should == 1
    end

  end
  context "extension merging" do
    before :all do
      @config = R509::Config::CAConfig.new( :ca_cert => R509::Cert.new( :cert => TestFixtures::TEST_CA_CERT) )
      @csr = R509::CSR.new(:csr => TestFixtures::CSR)
      profile = R509::Config::CertProfile.new(
        :ocsp_no_check => { :value => true },
        :key_usage => { :value => ['digitalSignature'] }
      )
      @config.set_profile("profile",profile)
      @builder = R509::CertificateAuthority::OptionsBuilder.new(@config)
    end

    it "adds extensions that don't exist in the profile" do
      exts = [R509::Cert::Extensions::ExtendedKeyUsage.new(:value => ['timeStamping']), R509::Cert::Extensions::InhibitAnyPolicy.new(:value => 1)]
      data = @builder.build_and_enforce(:csr => @csr, :extensions => exts, :profile_name => 'profile')
      data[:extensions].size.should == 6
      data[:extensions].select{ |el| el.kind_of?(R509::Cert::Extensions::InhibitAnyPolicy) }.size.should == 1
      data[:extensions].select{ |el| el.kind_of?(R509::Cert::Extensions::ExtendedKeyUsage) }.size.should == 1
      data[:extensions].select{ |el| el.kind_of?(R509::Cert::Extensions::KeyUsage) }.size.should == 1
      data[:extensions].select{ |el| el.kind_of?(R509::Cert::Extensions::OCSPNoCheck) }.size.should == 1
    end
    it "replaces extensions that already exist in the profile" do
      exts = [R509::Cert::Extensions::KeyUsage.new(:value => ['digitalSignature'])]
      data = @builder.build_and_enforce(:csr => @csr, :extensions => exts, :profile_name => 'profile')
      data[:extensions].size.should == 4
      data[:extensions].select{ |el| el.kind_of?(R509::Cert::Extensions::OCSPNoCheck) }.size.should == 1
      ku = data[:extensions].select{ |el| el.kind_of?(R509::Cert::Extensions::KeyUsage) }
      ku[0].allowed_uses.should == ['digitalSignature']
    end
  end

  context "enforces message_digest without an allowed_message_digests array in the profile" do
    before :all do
      config = R509::Config::CAConfig.new( :ca_cert => R509::Cert.new( :cert => TestFixtures::TEST_CA_CERT) )
      profile = R509::Config::CertProfile.new(
        :default_md => "SHA512"
      )
      config.set_profile("profile",profile)
      @builder = R509::CertificateAuthority::OptionsBuilder.new(config)
      @csr = R509::CSR.new(:csr => TestFixtures::CSR)
    end
    it "issues with all digest types" do
      R509::MessageDigest::KNOWN_MDS.each do |md|
        options = {
          :csr => R509::CSR.new(:csr => @csr),
          :message_digest => md,
          :profile_name => 'profile'
        }
        enforced = @builder.build_and_enforce(options)
        enforced[:message_digest].upcase.should == md
      end
    end
  end
  context "enforces message_digest with an allowed_message_digests array in the profile" do
    before :all do
      config = R509::Config::CAConfig.new( :ca_cert => R509::Cert.new( :cert => TestFixtures::TEST_CA_CERT) )
      profile = R509::Config::CertProfile.new(
        :basic_constraints => { :ca => false },
        :key_usage => { :value => ["digitalSignature"] },
        :allowed_mds => ['sha256','sha1','sha384'],
        :default_md => 'sha1'
      )
      config.set_profile("profile",profile)
      @builder = R509::CertificateAuthority::OptionsBuilder.new(config)
      @csr = R509::CSR.new(:csr => TestFixtures::CSR)
    end
    it "passes a disallowed hash" do
      expect { @builder.build_and_enforce( :csr => @csr, :message_digest => 'md5', :profile_name => "profile") }.to raise_error(R509::R509Error,'The message digest passed is not allowed by this configuration. Allowed digests: SHA256, SHA1, SHA384')
    end
    it "permits an allowed hash (not default)" do
      data = @builder.build_and_enforce(:csr => @csr, :message_digest => "sha384" , :profile_name => "profile")
      data[:message_digest].should == 'sha384'
    end
    it "returns the default hash if no hash is passed" do
      data = @builder.build_and_enforce(:csr => @csr, :profile_name => "profile")
      data[:message_digest].should == 'sha1'
    end
  end

  context "enforces not_after" do
    before :all do
      config = R509::Config::CAConfig.new( :ca_cert => R509::Cert.new( :cert => TestFixtures::TEST_CA_CERT) )
      profile = R509::Config::CertProfile.new(
        :basic_constraints => { :ca => false },
        :key_usage => { :value => ["digitalSignature"] },
        :allowed_mds => ['sha256','sha1','sha384'],
        :default_md => 'sha1'
      )
      config.set_profile("profile",profile)
      @builder = R509::CertificateAuthority::OptionsBuilder.new(config)
      @csr = R509::CSR.new(:csr => TestFixtures::CSR)
    end

    it "allows not_before and not_after through" do
      not_before = Time.now - 3600
      not_after = Time.now + 3600
      hash = @builder.build_and_enforce(
        :csr => @csr,
        :message_digest => 'sha256',
        :profile_name => 'profile',
        :not_before => not_before,
        :not_after => not_after
      )
      hash[:not_before].should == not_before
      hash[:not_after].should == not_after
    end

    it "does not add a not_before or not_after key if not passed" do
      hash = @builder.build_and_enforce(
        :csr => @csr,
        :message_digest => 'sha256',
        :profile_name => 'profile'
      )
      hash.key?(:not_before).should be_false
      hash.key?(:not_after).should be_false
    end

    it "raises error when not_after is after the issuing CA's expiry" do
      expect do
        @builder.build_and_enforce(
          :csr => @csr,
          :message_digest => 'sha256',
          :profile_name => 'profile',
          :not_after => Time.now + 86400*7300*25
        )
      end.to raise_error(R509::R509Error,'The requested certificate lifetime would exceed the issuing CA.')
    end
  end

end
