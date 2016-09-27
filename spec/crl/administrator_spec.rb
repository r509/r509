require 'spec_helper'

describe R509::CRL::Administrator do
  before :each do
    @cert = TestFixtures::CERT
    @csr = TestFixtures::CSR
    @csr3 = TestFixtures::CSR3
    @test_ca_config = TestFixtures.test_ca_no_profile_config
    @test_ca_dsa_config = TestFixtures.test_ca_dsa_no_profile_config
  end

  it "signs CRL with no delegate certificate" do
    config = R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert
    )
    crl_admin = R509::CRL::Administrator.new(config)
    crl = crl_admin.generate_crl
    expect(crl.issuer.to_s).to eq('/C=US/ST=Illinois/L=Chicago/O=Ruby CA Project/CN=Test CA')
  end

  it "signs CRL with delegate certificate" do
    config = R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert,
      :crl_cert => TestFixtures.test_ca_crl_delegate
    )
    crl_admin = R509::CRL::Administrator.new(config)
    crl = crl_admin.generate_crl
    expect(crl.issuer.to_s).to eq('/C=US/ST=Illinois/L=Chicago/O=r509 LLC/CN=r509 CRL Delegate')
  end

  it "signs CRL with non-default message digest" do
    config = R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert,
      :crl_md => 'sha256'
    )
    crl_admin = R509::CRL::Administrator.new(config)
    crl = crl_admin.generate_crl
    expect(crl.signature_algorithm).to eq('sha256WithRSAEncryption')
  end

  it "signs CRL with default message digest" do
    config = R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert
    )
    crl_admin = R509::CRL::Administrator.new(config)
    crl = crl_admin.generate_crl
    expect(crl.signature_algorithm).to eq('sha256WithRSAEncryption')
  end

  it "generates CRL with no entries in revocation list (RSA key)" do
    crl_admin = R509::CRL::Administrator.new(@test_ca_config)
    crl = crl_admin.generate_crl
    expect(crl.to_pem).to match(/BEGIN X509 CRL/)
    expect(crl.signature_algorithm).to eq('sha256WithRSAEncryption')
  end
  it "generates CRL with no entries in revocation list (DSA key)" do
    crl_admin = R509::CRL::Administrator.new(@test_ca_dsa_config)
    crl = crl_admin.generate_crl
    expect(crl.to_pem).to match(/BEGIN X509 CRL/)
    expect(crl.signature_algorithm).to eq('dsa_with_SHA256')
  end
  context "elliptic curve", :ec => true do
    before :all do
      @test_ca_ec_config = TestFixtures.test_ca_ec_no_profile_config
    end
    it "generates CRL with no entries in revocation list (EC key)" do
      crl_admin = R509::CRL::Administrator.new(@test_ca_ec_config)
      crl = crl_admin.generate_crl
      expect(crl.to_pem).to match(/BEGIN X509 CRL/)
      expect(crl.signature_algorithm).to eq('ecdsa-with-SHA256')
    end
  end
  it "raises exception when no R509::Config::CAConfig object is passed to the constructor" do
    expect { R509::CRL::Administrator.new(['random']) }.to raise_error(R509::R509Error)
  end
  it "raises exception when reader/writer is passed that is not a subclass of ReaderWriter)" do
    expect { R509::CRL::Administrator.new(@test_ca_config, {}) }.to raise_error(ArgumentError, 'argument reader_writer must be a subclass of R509::CRL::ReaderWriter')
  end
  it "adds a cert to the revocation list" do
    crl_admin = R509::CRL::Administrator.new(@test_ca_config)
    expect(crl_admin.revoked?(383834832)).to eq(false)
    crl_admin.revoke_cert(383834832)
    expect(crl_admin.revoked?(383834832)).to eq(true)
    expect(crl_admin.revoked?('383834832')).to eq(true)
    crl = crl_admin.generate_crl
    expect(crl.revoked[383834832]).not_to be_nil
    expect(crl.crl.revoked[0].serial).to eq(383834832)
  end
  it "can revoke (with reason)" do
    crl_admin = R509::CRL::Administrator.new(@test_ca_config)
    expect(crl_admin.revoked?(12345)).to eq(false)
    crl_admin.revoke_cert(12345, 1)
    expect(crl_admin.revoked?(12345)).to eq(true)
    expect(crl_admin.revoked_cert(12345)[:reason]).to eq(1)
    crl = crl_admin.generate_crl

    expect(crl.crl.revoked[0].serial).to eq(12345)
    expect(crl.crl.revoked[0].extensions[0].oid).to eq("CRLReason")
    expect(crl.crl.revoked[0].extensions[0].value).to eq("Key Compromise")
  end
  it "can revoke (without reason)" do
    crl_admin = R509::CRL::Administrator.new(@test_ca_config)
    expect(crl_admin.revoked?(12345)).to eq(false)
    crl_admin.revoke_cert(12345)
    expect(crl_admin.revoked?(12345)).to eq(true)
    expect(crl_admin.revoked_cert(12345)[:reason]).to be_nil
    crl = crl_admin.generate_crl

    expect(crl.crl.revoked[0].serial).to eq(12345)
    expect(crl.crl.revoked[0].extensions.size).to eq(0)
  end
  it "cannot revoke the same serial twice" do
    crl = R509::CRL::Administrator.new(@test_ca_config)
    expect(crl.revoked?(12345)).to eq(false)
    crl.revoke_cert(12345, 1)
    expect(crl.revoked?(12345)).to eq(true)
    expect(crl.revoked_cert(12345)[:reason]).to eq(1)
    expect { crl.revoke_cert(12345, 1) }.to raise_error(R509::R509Error, "Cannot revoke a previously revoked certificate")
    expect(crl.revoked?(12345)).to eq(true)
  end
  it "adds a cert to the revocation list with an invalid reason code" do
    crl = R509::CRL::Administrator.new(@test_ca_config)
    expect { crl.revoke_cert(383834832, 15) }.to raise_error(ArgumentError, 'Revocation reason must be integer 0-10 (excluding 7) or nil')
    expect { crl.revoke_cert(383834832, 7) }.to raise_error(ArgumentError, 'Revocation reason must be integer 0-10 (excluding 7) or nil')
    expect { crl.revoke_cert(383834832, 'string') }.to raise_error(ArgumentError, 'Revocation reason must be integer 0-10 (excluding 7) or nil')
  end
  it "removes a cert from the revocation list" do
    crl_admin = R509::CRL::Administrator.new(@test_ca_config)
    crl_admin.revoke_cert(383834832)
    expect(crl_admin.revoked?(383834832)).to eq(true)
    crl = crl_admin.generate_crl
    expect(crl.crl.revoked[0].serial).to eq(383834832)
    crl_admin.unrevoke_cert(383834832)
    crl = crl_admin.generate_crl
    expect(crl_admin.revoked?(383834832)).to eq(false)
    expect(crl.crl.revoked.empty?).to eq(true)
  end
  it "loads an existing revocation list file" do
    config = R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert,
      :crl_list_file => TestFixtures::CRL_LIST_FILE
    )
    crl = R509::CRL::Administrator.new(config)
    expect(crl.revoked?(12345)).to eq(true)
    expect(crl.revoked_cert(12345)[:revoke_time]).to eq(1323983885)
    expect(crl.revoked_cert(12345)[:reason]).to eq(0)
    expect(crl.revoked?(12346)).to eq(true)
    expect(crl.revoked_cert(12346)[:revoke_time]).to eq(1323983885)
    expect(crl.revoked_cert(12346)[:reason]).to be_nil
  end
  it "load when nil crl_list_file" do
    config = R509::Config::CAConfig.new(
      :ca_cert => TestFixtures.test_ca_cert,
      :crl_list_file => nil
    )
    expect { R509::CRL::Administrator.new(config) }.to_not raise_error
  end
  it "sets validity via yaml" do
    crl_admin = R509::CRL::Administrator.new(@test_ca_config)
    t = Time.at Time.now.to_i
    expect(Time).to receive(:now).twice.and_return(t)
    crl = crl_admin.generate_crl
    expect(crl.next_update).to eq(t.utc + 168 * 3600) # default 168 hours (7 days)
  end
  it "has proper defaults for last_update and next_update" do
    crl_admin = R509::CRL::Administrator.new(@test_ca_config)
    now = Time.at Time.now.to_i
    crl = crl_admin.generate_crl
    expect(crl.last_update).to eq(now - @test_ca_config.crl_start_skew_seconds)
    expect(crl.next_update).to eq(now + @test_ca_config.crl_validity_hours * 3600)
  end
  it "takes custom last_update and next_update" do
    crl_admin = R509::CRL::Administrator.new(@test_ca_config)
    last = Time.at Time.now.to_i - 86400
    nex = Time.at Time.now.to_i + 5
    crl = crl_admin.generate_crl(last, nex)
    expect(crl.last_update).to eq(last)
    expect(crl.next_update).to eq(nex)
  end
  it "calls write_list_entry when revoking" do
    rw = double("rw")
    expect(rw).to receive(:is_a?).and_return(true)
    expect(rw).to receive(:write_list_entry)
    expect(rw).to receive(:read_number).and_return(0)
    expect(rw).to receive(:read_list).and_return(nil)
    crl_admin = R509::CRL::Administrator.new(@test_ca_config, rw)
    expect(crl_admin.revoked?(383834832)).to eq(false)
    crl_admin.revoke_cert(383834832)
  end
  it "calls write_number when incrementing crl_number" do
    rw = double("rw")
    expect(rw).to receive(:is_a?).and_return(true)
    expect(rw).to receive(:read_number).and_return(0)
    expect(rw).to receive(:read_list).and_return(nil)
    expect(rw).to receive(:write_number).with(1)
    crl_admin = R509::CRL::Administrator.new(@test_ca_config, rw)
    crl_admin.generate_crl
  end
end
