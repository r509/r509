require 'spec_helper'

describe R509::Cert do
  before :all do
    @cert = TestFixtures::CERT
    @cert_public_key_modulus = TestFixtures::CERT_PUBLIC_KEY_MODULUS
    @cert3 = TestFixtures::CERT3
    @cert_ocsp_no_check = TestFixtures::CERT_OCSP_NO_CHECK
    @cert_der = TestFixtures::CERT_DER
    @cert_san = TestFixtures::CERT_SAN
    @cert_san2 = TestFixtures::CERT_SAN2
    @key3 = TestFixtures::KEY3
    @cert3_p12 = TestFixtures::CERT3_P12
    @cert4 = TestFixtures::CERT4
    @key3_encrypted = TestFixtures::KEY3_ENCRYPTED
    @cert5 = TestFixtures::CERT5
    @cert6 = TestFixtures::CERT6
    @test_ca_cert = TestFixtures::TEST_CA_CERT
    @cert_expired = TestFixtures::CERT_EXPIRED
    @cert_not_yet_valid = TestFixtures::CERT_NOT_YET_VALID
    @cert_inhibit = TestFixtures::CERT_INHIBIT
    @cert_policy_constraints = TestFixtures::CERT_POLICY_CONSTRAINTS
    @cert_name_constraints = TestFixtures::CERT_NAME_CONSTRAINTS
  end
  it "raises error when no hash supplied" do
    expect { R509::Cert.new('no hash') }.to raise_error(ArgumentError, 'Must provide a hash of options')
  end
  it "raises error when no :cert supplied" do
    expect { R509::Cert.new(:key => "random") }.to raise_error(ArgumentError, 'Must provide :cert or :pkcs12')
  end
  it "raises error when a csr is supplied to :cert" do
    expect { R509::Cert.new(:cert => TestFixtures::CSR) }.to raise_error(ArgumentError, "Cert provided is actually a certificate signing request.")
  end
  it "raises error when :cert and :pkcs12 are both provided" do
    expect do
      R509::Cert.new(
        :key => @key3,
        :pkcs12 => @cert3_p12,
        :password => 'whatever'
      )
    end.to raise_error(ArgumentError, 'When providing pkcs12, do not pass cert or key')
  end
  it "raises error when :key and :pkcs12 are both provided" do
    expect do
      R509::Cert.new(
        :cert => @cert,
        :pkcs12 => @cert3_p12,
        :password => 'whatever'
      )
    end.to raise_error(ArgumentError, 'When providing pkcs12, do not pass cert or key')
  end
  it "has a public_key" do
    cert = R509::Cert.new(:cert => @cert)
    # this is more complex than it should have to be. diff versions of openssl
    # return subtly diff PEM encodings so we need to look at the modulus (n)
    # but beware, because n is not present for DSA certificates
    expect(cert.public_key.n.to_i).to eq(@cert_public_key_modulus.to_i)
  end
  it "returns bit strength" do
    cert = R509::Cert.new(:cert => @cert)
    expect(cert.bit_strength).to eq(2048)
  end
  it "has the right issuer" do
    cert = R509::Cert.new(:cert => @cert)
    expect(cert.issuer.to_s).to eq("/C=US/O=SecureTrust Corporation/CN=SecureTrust CA")
  end
  it "generates certificate fingerprints" do
    cert = R509::Cert.new(:cert => @cert)
    expect(cert.fingerprint).to eq('863bbb58877b426eb10ccfd34d3056b8c961f627')
    expect(cert.fingerprint('sha256')).to eq('65d624f5a6937c3005d78b3f4ff09164649dd5aeb3fd8a93d6fd420e8b587fa2')
    expect(cert.fingerprint('sha512')).to eq('a07d87f04161f52ef671c9d616530d07ebadef9c93c0470091617363c9ce8618dcb7931414e599d25cb032d68597111719e76d7de4bb7a92bf5ca7c08c36cf12')
    expect(cert.fingerprint('md5')).to eq('aa78501c41b19252dfbe8ba509cc21f4')
  end
  it "returns true from has_private_key? when a key is present" do
    cert = R509::Cert.new(:cert => @cert3, :key => @key3)
    expect(cert.has_private_key?).to eq(true)
  end
  it "returns false from has_private_key? when a key is not present" do
    cert = R509::Cert.new(:cert => @cert)
    expect(cert.has_private_key?).to eq(false)
  end
  it "loads encrypted private key with cert" do
    expect { R509::Cert.new(:cert => @cert3, :key => @key3_encrypted, :password => "r509") }.to_not raise_error
  end
  it "loads pkcs12" do
    cert = R509::Cert.new(:pkcs12 => @cert3_p12, :password => "r509")
    expect(cert.has_private_key?).to eq(true)
    expect(cert.subject.to_s).to eq('/CN=futurama.com/O=Farnsworth Enterprises')
  end
  it "has the right not_before" do
    cert = R509::Cert.new(:cert => @cert)
    expect(cert.not_before.to_i).to eq(1282659002)
  end
  it "has the right not_after" do
    cert = R509::Cert.new(:cert => @cert)
    expect(cert.not_after.to_i).to eq(1377267002)
  end
  it "returns signature algorithm" do
    cert = R509::Cert.new(:cert => @cert)
    expect(cert.signature_algorithm).to eq('sha1WithRSAEncryption')
  end
  it "returns the RSA key algorithm" do
    cert = R509::Cert.new(:cert => @cert)
    expect(cert.key_algorithm).to eq("RSA")
  end
  it "returns the DSA key algorithm" do
    cert = R509::Cert.new(:cert => @cert6)
    expect(cert.key_algorithm).to eq("DSA")
  end
  it "returns list of san names when it is a san cert" do
    cert = R509::Cert.new(:cert => @cert_san)
    expect(cert.san.dns_names).to eq(['langui.sh'])
  end
  it "#san returns nil when it is not a san cert" do
    cert = R509::Cert.new(:cert => @cert)
    expect(cert.san).to be_nil
  end
  it "#all_names should return a list of san names in addition to the CN" do
    cert = R509::Cert.new(:cert => @cert_san2)
    expect(cert.all_names).to eq(["cn.langui.sh", "san1.langui.sh",
                              "san2.langui.sh", "san3.langui.sh"])
  end
  it "#all_names should not have duplicates" do
    cert = R509::Cert.new(:cert => @cert_san)
    expect(cert.all_names).to eq(["langui.sh"])
  end
  it "#all_names should return the CN in the array even if there are no SANs" do
    cert = R509::Cert.new(:cert => @cert)
    expect(cert.all_names).to eq(["langui.sh"])
  end
  it "raises exception when providing invalid cert" do
    expect { R509::Cert.new(:cert => "invalid cert") }.to raise_error(OpenSSL::X509::CertificateError)
  end
  it "raises exception when providing invalid key" do
    expect { R509::Cert.new(:cert => @cert, :key => 'invalid key') }.to raise_error(R509::R509Error, 'Failed to load private key. Invalid key or incorrect password.')
  end
  it "raises exception on non-matching key" do
    expect { R509::Cert.new(:cert => @cert, :key => @key3) }.to raise_error(R509::R509Error, 'Key does not match cert.')
  end
  it "return normal object on matching key/cert pair" do
    expect { R509::Cert.new(:cert => @cert3, :key => @key3) }.to_not raise_error
  end
  it "loads properly when an R509::PrivateKey is provided" do
    key = R509::PrivateKey.new(:key => @key3)
    expect { R509::Cert.new(:key => key, :cert => @cert3) }.to_not raise_error
  end
  it "writes to pem" do
    cert = R509::Cert.new(:cert => @cert)
    sio = StringIO.new
    sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
    cert.write_pem(sio)
    expect(sio.string).to eq(@cert)
  end
  it "writes to der" do
    cert = R509::Cert.new(:cert => @cert)
    sio = StringIO.new
    sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
    cert.write_der(sio)
    expect(sio.string).to eq(@cert_der)
  end
  it "writes to pkcs12 when key/cert are present" do
    cert = R509::Cert.new(:cert => @cert3, :key => @key3)
    sio = StringIO.new
    sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
    cert.write_pkcs12(sio, 'r509_password')
    expect { R509::Cert.new(:pkcs12 => sio.string, :password => 'r509_password') }.to_not raise_error
  end
  it "raises error when writing to pkcs12 if key is not present" do
    cert = R509::Cert.new(:cert => @cert3)
    expect { cert.write_pkcs12('/dev/null', 'password') }.to raise_error(R509::R509Error, "Writing a PKCS12 requires both key and cert")
  end
  it "parses san extension" do
    cert = R509::Cert.new(:cert => @cert_san)
    expect(cert.san.dns_names).to eq(["langui.sh"])
  end
  context "when initialized with an OpenSSL::X509::Certificate" do
    it "returns pem on to_pem" do
      test_cert = OpenSSL::X509::Certificate.new(@cert)
      cert = R509::Cert.new(:cert => test_cert)
      expect(cert.to_pem).to eq(@cert)
    end
    it "returns der on to_der" do
      test_cert = OpenSSL::X509::Certificate.new(@cert)
      cert = R509::Cert.new(:cert => test_cert)
      expect(cert.to_der).to eq(@cert_der)
    end
    it "returns pem on to_s" do
      test_cert = OpenSSL::X509::Certificate.new(@cert)
      cert = R509::Cert.new(:cert => test_cert)
      expect(cert.to_s).to eq(@cert)
    end
  end
  context "when initialized with a pem" do
    it "returns on to_pem" do
      cert = R509::Cert.new(:cert => @cert)
      expect(cert.to_pem).to eq(@cert)
    end
    it "returns der on to_der" do
      cert = R509::Cert.new(:cert => @cert)
      expect(cert.to_der).to eq(@cert_der)
    end
    it "returns pem on to_s" do
      cert = R509::Cert.new(:cert => @cert)
      expect(cert.to_s).to eq(@cert)
    end
  end
  it "gets the right object from #basic_constraints" do
    cert = R509::Cert.new(:cert => @cert)
    expect(cert.basic_constraints.class).to eq(R509::Cert::Extensions::BasicConstraints)
  end
  it "gets the right object from #key_usage" do
    cert = R509::Cert.new(:cert => @cert)
    expect(cert.key_usage.class).to eq(R509::Cert::Extensions::KeyUsage)
  end
  it "gets the right object from #key_usage" do
    cert = R509::Cert.new(:cert => @cert)
    expect(cert.extended_key_usage.class).to eq(R509::Cert::Extensions::ExtendedKeyUsage)
  end
  it "gets the right object from #subject_key_identifier" do
    cert = R509::Cert.new(:cert => @cert)
    expect(cert.subject_key_identifier.class).to eq(R509::Cert::Extensions::SubjectKeyIdentifier)
  end
  it "gets the right object from #authority_key_identifier" do
    cert = R509::Cert.new(:cert => @cert)
    expect(cert.authority_key_identifier.class).to eq(R509::Cert::Extensions::AuthorityKeyIdentifier)
  end
  it "gets the right object from #subject_alternative_name" do
    cert = R509::Cert.new(:cert => @cert5)
    expect(cert.subject_alternative_name.class).to eq(R509::Cert::Extensions::SubjectAlternativeName)
  end
  it "gets the right object from #authority_info_access" do
    cert = R509::Cert.new(:cert => @cert5)
    expect(cert.authority_info_access.class).to eq(R509::Cert::Extensions::AuthorityInfoAccess)
  end
  it "gets the right object from #crl_distribution_points" do
    cert = R509::Cert.new(:cert => @cert)
    expect(cert.crl_distribution_points.class).to eq(R509::Cert::Extensions::CRLDistributionPoints)
  end
  it "gets the right object from #certificate_policies" do
    cert = R509::Cert.new(:cert => @cert)
    expect(cert.certificate_policies.class).to eq(R509::Cert::Extensions::CertificatePolicies)
  end
  it "gets the right object from #inhibit_any_policy" do
    cert = R509::Cert.new(:cert => @cert_inhibit)
    expect(cert.inhibit_any_policy.class).to eq(R509::Cert::Extensions::InhibitAnyPolicy)
  end
  it "gets the right object from #policy_constraints" do
    cert = R509::Cert.new(:cert => @cert_policy_constraints)
    expect(cert.policy_constraints.class).to eq(R509::Cert::Extensions::PolicyConstraints)
  end
  it "gets the right object from #name_constraints" do
    cert = R509::Cert.new(:cert => @cert_name_constraints)
    expect(cert.name_constraints.class).to eq(R509::Cert::Extensions::NameConstraints)
  end
  it "returns true from #ocsp_no_check? when the extension is present" do
    cert = R509::Cert.new(:cert => @cert_ocsp_no_check)
    expect(cert.ocsp_no_check?).to eq(true)
  end
  it "returns false from #ocsp_no_check? when the extension is not present" do
    cert = R509::Cert.new(:cert => @cert)
    expect(cert.ocsp_no_check?).to eq(false)
  end

  it "checks rsa?" do
    cert = R509::Cert.new(:cert => @cert)
    expect(cert.rsa?).to eq(true)
    expect(cert.ec?).to eq(false)
    expect(cert.dsa?).to eq(false)
  end
  it "gets RSA bit strength" do
    cert = R509::Cert.new(:cert => @cert)
    expect(cert.bit_strength).to eq(2048)
  end
  it "returns an error for curve_name for DSA/RSA" do
    cert = R509::Cert.new(:cert => @cert)
    expect { cert.curve_name }.to raise_error(R509::R509Error, 'Curve name is only available with EC')
  end
  it "checks dsa?" do
    cert = R509::Cert.new(:cert => @cert6)
    expect(cert.rsa?).to eq(false)
    expect(cert.ec?).to eq(false)
    expect(cert.dsa?).to eq(true)
  end
  it "gets DSA bit strength" do
    cert = R509::Cert.new(:cert => @cert6)
    expect(cert.bit_strength).to eq(1024)
  end
  it "gets serial of cert" do
    cert = R509::Cert.new(:cert => @cert6)
    expect(cert.serial).to eq(951504)
  end
  it "gets hexserial of cert" do
    cert = R509::Cert.new(:cert => @cert6)
    expect(cert.hexserial).to eq("0E84D0")
  end
  it "checks a cert that is not yet valid" do
    cert = R509::Cert.new(:cert => @cert_not_yet_valid)
    expect(cert.valid?).to eq(false)
  end
  it "checks a cert that is in validity range" do
    cert = R509::Cert.new(:cert => @test_ca_cert)
    expect(cert.valid?).to eq(true)
  end
  it "checks a cert that is expired" do
    cert = R509::Cert.new(:cert => @cert_expired)
    expect(cert.valid?).to eq(false)
  end
  it "checks expired_at?" do
    cert = R509::Cert.new(:cert => @cert_expired)
    expect(cert.valid_at?(Time.utc(2009, 1, 1))).to eq(false)
    expect(cert.valid_at?(Time.utc(2011, 3, 1))).to eq(true)
    expect(cert.valid_at?(1298959200)).to eq(true)
    expect(cert.valid_at?(Time.utc(2012, 1, 1))).to eq(false)
  end
  it "is revoked by crl" do
    cert = R509::Cert.new(:cert => @cert3)
    crl_admin = R509::CRL::Administrator.new(TestFixtures.test_ca_config)
    crl_admin.revoke_cert(1425751142578902223005775172931960716533532010870)
    crl = crl_admin.generate_crl
    expect(cert.is_revoked_by_crl?(crl)).to eq(true)
  end
  it "is not revoked by crl" do
    cert = R509::Cert.new(:cert => @cert3)
    crl_admin = R509::CRL::Administrator.new(TestFixtures.test_ca_config)
    crl = crl_admin.generate_crl
    expect(cert.is_revoked_by_crl?(crl)).to eq(false)
  end
  it "loads a cert with load_from_file" do
    path = File.dirname(__FILE__) + '/fixtures/cert1.pem'
    cert = R509::Cert.load_from_file path
    expect(cert.serial.to_i).to eq(211653423715)
  end
  it "returns a hash for #extensions" do
    cert = R509::Cert.new(:cert => @cert3)
    expect(cert.extensions.kind_of?(Hash)).to eq(true)
  end
  it "returns an array for #unknown_extensions" do
    cert = R509::Cert.new(:cert => @cert3)
    expect(cert.unknown_extensions).to eq([])
  end

  context "elliptic curve certs", :ec => true do
    before :all do
      @cert_ec = TestFixtures::EC_EE_CERT
      @key_ec = TestFixtures::EC_EE_KEY
    end
    it "loads a cert" do
      expect { R509::Cert.new(:cert => @cert_ec) }.to_not raise_error
    end
    it "writes to pkcs12 when key/cert are present" do
      cert = R509::Cert.new(:cert => @cert_ec, :key => @key_ec)
      sio = StringIO.new
      sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
      cert.write_pkcs12(sio, 'r509_password')
      expect { R509::Cert.new(:pkcs12 => sio.string, :password => 'r509_password') }.to_not raise_error
    end
    it "raises error on bit strength" do
      cert = R509::Cert.new(:cert => @cert_ec)
      expect { cert.bit_strength }.to raise_error(R509::R509Error, 'Bit length is not available for EC at this time.')
    end
    it "returns curve name" do
      cert = R509::Cert.new(:cert => @cert_ec)
      expect(cert.curve_name).to eq('secp384r1')
    end
    it "checks ec?" do
      cert = R509::Cert.new(:cert => @cert_ec)
      expect(cert.rsa?).to eq(false)
      expect(cert.dsa?).to eq(false)
      expect(cert.ec?).to eq(true)
    end
    it "returns the public key" do
      cert = R509::Cert.new(:cert => @cert_ec)
      private_key = R509::PrivateKey.new(:key => @key_ec)
      expect(cert.public_key.to_der).to eq(private_key.public_key.to_der)
    end
    it "returns the key algorithm" do
      cert = R509::Cert.new(:cert => @cert_ec)
      expect(cert.key_algorithm).to eq("EC")
    end
  end

  context "when elliptic curve support is unavailable" do
    before :all do
      @ec = OpenSSL::PKey.send(:remove_const, :EC) # remove EC support for test!
      load('r509/ec-hack.rb')
    end
    after :all do
      OpenSSL::PKey.send(:remove_const, :EC) # remove stubbed EC
      OpenSSL::PKey::EC = @ec # add the real one back
    end
    it "checks rsa?" do
      cert = R509::Cert.new(:cert => @cert)
      expect(cert.rsa?).to eq(true)
      expect(cert.ec?).to eq(false)
      expect(cert.dsa?).to eq(false)
    end
    it "returns RSA key algorithm for RSA CSR" do
      cert = R509::Cert.new(:cert => @cert)
      expect(cert.key_algorithm).to eq("RSA")
    end
  end
end
