require 'spec_helper'
require 'stringio'
require 'r509/csr'

describe R509::CSR do
  before :all do
    @csr = TestFixtures::CSR
    @csr_newlines = TestFixtures::CSR_NEWLINES
    @csr_no_begin_end = TestFixtures::CSR_NO_BEGIN_END
    @csr_der = TestFixtures::CSR_DER
    @csr_public_key_modulus = TestFixtures::CSR_PUBLIC_KEY_MODULUS
    @csr_invalid_signature = TestFixtures::CSR_INVALID_SIGNATURE
    @csr2 = TestFixtures::CSR2
    @csr3 = TestFixtures::CSR3
    @csr_der = TestFixtures::CSR_DER
    @csr_dsa = TestFixtures::CSR_DSA
    @csr4_multiple_attrs = TestFixtures::CSR4_MULTIPLE_ATTRS
    @key3 = TestFixtures::KEY3
    @key_csr2 = TestFixtures::KEY_CSR2
    @dsa_key = TestFixtures::DSA_KEY
    @csr_unknown_oid = TestFixtures::CSR_UNKNOWN_OID
    @ec_csr2_pem = TestFixtures::EC_CSR2_PEM
    @ec_csr2_der = TestFixtures::EC_CSR2_DER
  end

  it "raises an exception when passing non-hash" do
    expect { R509::CSR.new('invalid') }.to raise_error(ArgumentError, 'Must provide a hash of options')
  end
  it "key creation defaults to RSA when no type or key is passed" do
    csr = R509::CSR.new(:subject => [['CN', 'testing.rsa']], :bit_length => 1024)
    expect(csr.rsa?).to eq(true)
    expect(csr.dsa?).to eq(false)
    expect(csr.ec?).to eq(false)
  end
  it "returns expected value for to_der" do
    csr = R509::CSR.new(:csr => @csr)
    expect(csr.to_der).to eq(@csr_der)
  end
  it "loads a csr with extraneous newlines" do
    csr = R509::CSR.new(:csr => @csr_newlines)
    expect(csr.to_pem).to match(/-----BEGIN CERTIFICATE REQUEST-----/)
  end
  it "loads a csr with no begin/end lines" do
    csr = R509::CSR.new(:csr => @csr_no_begin_end)
    expect(csr.to_pem).to match(/-----BEGIN CERTIFICATE REQUEST-----/)
  end
  it "returns true from #has_private_key? when private key is present" do
    csr = R509::CSR.new(:bit_length => 512, :subject => [['CN', 'private-key-check.com']])
    expect(csr.has_private_key?).to eq(true)
  end
  it "returns false from #has_private_key? when private key is not present" do
    csr = R509::CSR.new(:csr => @csr)
    expect(csr.has_private_key?).to eq(false)
  end
  it "key creation defaults to 2048 when no bit length or key is passed" do
    csr = R509::CSR.new(:subject => [['CN', 'testing2048.rsa']])
    expect(csr.bit_length).to eq(2048)
  end
  it "creates a CSR when a key is provided" do
    csr = R509::CSR.new(:key => @key3, :subject => [['CN', 'pregenerated.com']], :bit_length => 1024)
    expect(csr.to_pem).to match(/CERTIFICATE REQUEST/)
    # validate the CSR matches the key
    expect(csr.req.verify(csr.key.public_key)).to eq(true)
  end
  it "loads successfully when an R509::PrivateKey is provided" do
    key = R509::PrivateKey.new(:key => @key3)
    expect { R509::CSR.new(:key => key, :csr => @csr3) }.to_not raise_error
  end
  it "raises an exception when you pass :subject and :csr" do
    expect { R509::CSR.new(:subject => [['CN', 'error.com']], :csr => @csr) }.to raise_error(ArgumentError, 'You must provide :subject or :csr, not both')
  end
  it "raises an exception for not providing valid type when key is nil" do
    expect { R509::CSR.new(:subject => [['CN', 'error.com']], :type => :invalid_symbol) }.to raise_error(ArgumentError, "Must provide #{R509::PrivateKey::KNOWN_TYPES.join(", ")} as type when key is nil")
  end
  it "raises an exception when you don't provide :subject or :csr" do
    expect { R509::CSR.new(:bit_length => 1024) }.to raise_error(ArgumentError, 'You must provide :subject or :csr')
  end
  it "raises an exception if you provide a list of domains with an existing CSR" do
    expect { R509::CSR.new(:csr => @csr, :san_names => ['moredomainsiwanttoadd.com']) }.to raise_error(ArgumentError, 'You can\'t add domains to an existing CSR')
  end
  it "changes the message_digest to DSS1 when passed a DSA key" do
    csr = R509::CSR.new(:subject => [["CN", "dsasigned.com"]], :key => @dsa_key)
    expect(csr.message_digest.name).to eq('dss1')
    expect(csr.signature_algorithm).to eq('dsaWithSHA1')
    # dss1 is actually the same as SHA1
    # Yes this is confusing
    # see http://www.ruby-doc.org/stdlib-1.9.3/libdoc/openssl/rdoc/OpenSSL/PKey/DSA.html
  end
  it "changes the message_digest to DSS1 when creating a DSA key" do
    csr = R509::CSR.new(:subject => [["CN", "dsasigned.com"]], :type => "dsa", :bit_length => 512)
    expect(csr.message_digest.name).to eq('dss1')
    expect(csr.signature_algorithm).to eq('dsaWithSHA1')
    # dss1 is actually the same as SHA1
    # Yes this is confusing
    # see http://www.ruby-doc.org/stdlib-1.9.3/libdoc/openssl/rdoc/OpenSSL/PKey/DSA.html
  end
  it "signs a CSR properly when passed a DSA key" do
    csr = R509::CSR.new(:subject => [["CN", "dsasigned.com"]], :key => @dsa_key)
    expect(csr.verify_signature).to eq(true)
  end
  it "signs a CSR properly when creating a DSA key" do
    csr = R509::CSR.new(:subject => [["CN", "dsasigned.com"]], :type => "dsa", :bit_length => 512)
    expect(csr.verify_signature).to eq(true)
  end
  it "writes to pem" do
    csr = R509::CSR.new(:csr => @csr)
    sio = StringIO.new
    sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
    csr.write_pem(sio)
    expect(sio.string).to eq(@csr)
  end
  it "writes to der" do
    sio = StringIO.new
    sio.set_encoding("BINARY") if sio.respond_to?(:set_encoding)
    csr = R509::CSR.new(:csr => @csr)
    csr.write_der(sio)
    expect(sio.string).to eq(@csr_der)
  end
  it "duplicate SAN names should be removed" do
    csr = R509::CSR.new(:bit_length => 512, :subject => [['CN', 'test2345.com']], :san_names => ["test2.local", "test.local", "test.local"])
    expect(csr.san.dns_names).to eq(["test2.local", "test.local"])
  end
  it "existing GeneralNames object passed to CSR should be used" do
    gn = R509::ASN1::GeneralNames.new
    gn.create_item(:type => 'dNSName', :value => '127.0.0.1')
    gn.create_item(:type => 'dNSName', :value => '127.0.0.2')
    csr = R509::CSR.new(:bit_length => 512, :subject => [['CN', 'test2345.com']], :san_names => gn)
    expect(csr.san.dns_names).to eq(["127.0.0.1", "127.0.0.2"])
  end
  it "san is nil when there are no SAN names" do
    csr = R509::CSR.new(:subject => [['CN', 'langui.sh'], ['emailAddress', 'ca@langui.sh']], :bit_length => 512)
    expect(csr.san.nil?).to eq(true)
  end
  context "when initialized" do
    it "raises exception when providing invalid csr" do
      expect { R509::CSR.new(:csr => 'invalid csr') }.to raise_error(OpenSSL::X509::RequestError)
    end
    it "raises exception when providing invalid key" do
      expect { R509::CSR.new(:csr => @csr, :key => 'invalid key') }.to raise_error(R509::R509Error, "Failed to load private key. Invalid key or incorrect password.")
    end
  end
  context "when passing a subject array" do
    it "generates a matching CSR" do
      csr = R509::CSR.new(:subject => [['CN', 'langui.sh'], ['ST', 'Illinois'], ['L', 'Chicago'], ['C', 'US'], ['emailAddress', 'ca@langui.sh']], :bit_length => 1024)
      expect(csr.subject.to_s).to eq('/CN=langui.sh/ST=Illinois/L=Chicago/C=US/emailAddress=ca@langui.sh')
    end
    it "generates a matching csr when supplying raw oids" do
      csr = R509::CSR.new(:subject => [['2.5.4.3', 'common name'], ['2.5.4.15', 'business category'], ['2.5.4.7', 'locality'], ['1.3.6.1.4.1.311.60.2.1.3', 'jurisdiction oid openssl typically does not know']], :bit_length => 1024)
      expect(csr.subject.to_s).to eq("/CN=common name/businessCategory=business category/L=locality/jurisdictionOfIncorporationCountryName=jurisdiction oid openssl typically does not know")
    end
    it "adds SAN names to a generated CSR" do
      csr = R509::CSR.new(:subject => [['CN', 'test']], :bit_length => 1024, :san_names => ['1.2.3.4', 'http://langui.sh', 'email@address.local', 'domain.internal', '2.3.4.5', [['CN', 'dirnametest']]])
      expect(csr.san.ip_addresses).to eq(['1.2.3.4', '2.3.4.5'])
      expect(csr.san.dns_names).to eq(['domain.internal'])
      expect(csr.san.uris).to eq(['http://langui.sh'])
      expect(csr.san.rfc_822_names).to eq(['email@address.local'])
      expect(csr.san.directory_names.size).to eq(1)
      expect(csr.san.directory_names[0].to_s).to eq('/CN=dirnametest')
    end
  end
  context "when supplying an existing csr" do
    it "populates the bit_length" do
      csr = R509::CSR.new(:csr => @csr)
      expect(csr.bit_length).to eq(2048)
    end
    it "populates the subject" do
      csr = R509::CSR.new(:csr => @csr)
      expect(csr.subject.to_s).to eq('/CN=test.local/O=Testing CSR')
    end
    it "parses the san names" do
      csr = R509::CSR.new(:csr => @csr)
      expect(csr.san.dns_names).to eq(["test.local", "additionaldomains.com", "saniam.com"])
    end
    it "parses san names when there are multiple non-SAN attributes" do
      csr = R509::CSR.new(:csr => @csr4_multiple_attrs)
      expect(csr.san.dns_names).to eq(["adomain.com", "anotherdomain.com", "justanexample.com"])
    end
    it "fetches a subject component" do
      csr = R509::CSR.new(:csr => @csr)
      expect(csr.subject_component('CN').to_s).to eq('test.local')
    end
    it "returns nil when subject component not found" do
      csr = R509::CSR.new(:csr => @csr)
      expect(csr.subject_component('OU')).to be_nil
    end
    it "returns the signature algorithm" do
      csr = R509::CSR.new(:csr => @csr)
      expect(csr.signature_algorithm).to eq('sha1WithRSAEncryption')
    end
    it "returns RSA key algorithm for RSA CSR" do
      csr = R509::CSR.new(:csr => @csr)
      expect(csr.key_algorithm).to eq("RSA")
    end
    it "returns DSA key algorithm for DSA CSR" do
      csr = R509::CSR.new(:csr => @csr_dsa)
      expect(csr.key_algorithm).to eq("DSA")
    end
    it "returns the public key" do
      # this is more complex than it should have to be. diff versions of openssl
      # return subtly diff PEM encodings so we need to look at the modulus (n)
      # but beware, because n is not present for DSA certificates
      csr = R509::CSR.new(:csr => @csr)
      expect(csr.public_key.n.to_i).to eq(@csr_public_key_modulus.to_i)
    end
    it "returns true with valid signature" do
      csr = R509::CSR.new(:csr => @csr)
      expect(csr.verify_signature).to eq(true)
    end
    it "returns false on invalid signature" do
      csr = R509::CSR.new(:csr => @csr_invalid_signature)
      expect(csr.verify_signature).to eq(false)
    end
    it "works when the CSR has unknown OIDs" do
      csr = R509::CSR.new(:csr => @csr_unknown_oid)
      expect(csr.subject["1.2.3.4.5.6.7.8.9.8.7.6.5.4.3.2.1.0.0"]).to eq("random oid!")
      expect(csr.subject["1.3.3.543.567.32.43.335.1.1.1"]).to eq("another random oid!")
    end
  end
  context "when supplying a key with csr" do
    it "raises exception on non-matching key" do
      expect { R509::CSR.new(:csr => @csr, :key => @key_csr2) }.to raise_error(R509::R509Error, 'Key does not match request.')
    end
    it "accepts matching key" do
      csr = R509::CSR.new(:csr => @csr2, :key => @key_csr2)
      expect(csr.to_pem).to eq(@csr2)
    end
  end
  context "when setting alternate signature algorithms" do
    it "sets sha1 if you pass an invalid message digest" do
      csr = R509::CSR.new(:message_digest => 'sha88', :bit_length => 512, :subject => [['CN', 'langui.sh']])
      expect(csr.message_digest.name).to eq('sha1')
      expect(csr.signature_algorithm).to eq("sha1WithRSAEncryption")
    end
    it "sets sha224 properly" do
      csr = R509::CSR.new(:message_digest => 'sha224', :bit_length => 512, :subject => [['CN', 'sha224-signature-alg.test']])
      expect(csr.message_digest.name).to eq('sha224')
      expect(csr.signature_algorithm).to eq("sha224WithRSAEncryption")
    end
    it "sets sha256 properly" do
      csr = R509::CSR.new(:message_digest => 'sha256', :bit_length => 512, :subject => [['CN', 'sha256-signature-alg.test']])
      expect(csr.message_digest.name).to eq('sha256')
      expect(csr.signature_algorithm).to eq("sha256WithRSAEncryption")
    end
    it "sets sha384 properly" do
      csr = R509::CSR.new(:message_digest => 'sha384', :bit_length => 768, :subject => [['CN', 'sha384-signature-alg.test']])
      expect(csr.message_digest.name).to eq('sha384')
      expect(csr.signature_algorithm).to eq("sha384WithRSAEncryption")
    end
    it "sets sha512 properly" do
      csr = R509::CSR.new(:message_digest => 'sha512', :bit_length => 1024, :subject => [['CN', 'sha512-signature-alg.test']])
      expect(csr.message_digest.name).to eq('sha512')
      expect(csr.signature_algorithm).to eq("sha512WithRSAEncryption")
    end
    it "sets md5 properly" do
      csr = R509::CSR.new(:message_digest => 'md5', :bit_length => 512, :subject => [['CN', 'md5-signature-alg.test']])
      expect(csr.message_digest.name).to eq('md5')
      expect(csr.signature_algorithm).to eq("md5WithRSAEncryption")
    end
  end
  it "checks rsa?" do
    csr = R509::CSR.new(:csr => @csr)
    expect(csr.rsa?).to eq(true)
    expect(csr.ec?).to eq(false)
    expect(csr.dsa?).to eq(false)
  end
  it "gets RSA bit length" do
    csr = R509::CSR.new(:csr => @csr)
    expect(csr.bit_length).to eq(2048)
  end
  it "returns an error for curve_name for dsa/rsa CSRs" do
    csr = R509::CSR.new(:csr => @csr)
    expect { csr.curve_name }.to raise_error(R509::R509Error, 'Curve name is only available with EC')
  end
  it "checks dsa?" do
    csr = R509::CSR.new(:csr => @csr_dsa)
    expect(csr.rsa?).to eq(false)
    expect(csr.ec?).to eq(false)
    expect(csr.dsa?).to eq(true)
  end
  it "gets DSA bit length" do
    csr = R509::CSR.new(:csr => @csr_dsa)
    expect(csr.bit_length).to eq(1024)
  end

  it "loads a csr with load_from_file" do
    path = File.dirname(__FILE__) + '/fixtures/csr1.pem'
    csr = R509::CSR.load_from_file path
    expect(csr.message_digest.name).to eq('sha1')
  end

  context "when using elliptic curves", :ec => true do
    it "loads a pre-existing EC CSR" do
      csr = R509::CSR.new(:csr => @ec_csr2_pem)
      expect(csr.to_der).to eq(@ec_csr2_der)
    end
    it "returns the curve name" do
      csr = R509::CSR.new(:csr => @ec_csr2_pem)
      expect(csr.curve_name).to eq("secp384r1")
    end
    it "generates a CSR with default curve" do
      csr = R509::CSR.new(:type => "EC", :subject => [["CN", "ec-test.local"]])
      expect(csr.curve_name).to eq("secp384r1")
    end
    it "generates a CSR with explicit curve" do
      csr = R509::CSR.new(:type => "EC", :curve_name => "sect283r1", :subject => [["CN", "ec-test.local"]])
      expect(csr.curve_name).to eq("sect283r1")
    end
    it "gets ECDSA bit length" do
      csr = R509::CSR.new(:csr => @ec_csr2_der)
      expect(csr.bit_length).to eq(384)
    end
    it "returns the key algorithm" do
      csr = R509::CSR.new(:csr => @ec_csr2_pem)
      expect(csr.key_algorithm).to eq("EC")
    end
    it "returns the public key" do
      csr = R509::CSR.new(:csr => @ec_csr2_pem)
      expect(csr.public_key.private_key?).to eq(false)
      expect(csr.public_key.public_key?).to eq(true)
    end
    it "checks ec?" do
      csr = R509::CSR.new(:csr => @ec_csr2_pem)
      expect(csr.ec?).to eq(true)
    end
    it "sets alternate signature properly for EC" do
      csr = R509::CSR.new(:message_digest => 'sha256', :type => "EC", :subject => [["CN", "ec-signature-alg.test"]])
      expect(csr.message_digest.name).to eq('sha256')
      expect(csr.signature_algorithm).to eq('ecdsa-with-SHA256')
    end
  end

  context "when elliptic curve support is unavailable" do
    before :all do
      @ec = OpenSSL::PKey.send(:remove_const, :EC) # remove EC support for test!
      load('r509/openssl/ec-hack.rb')
    end
    after :all do
      OpenSSL::PKey.send(:remove_const, :EC) # remove stubbed EC
      OpenSSL::PKey::EC = @ec # add the real one back
    end
    it "checks rsa?" do
      csr = R509::CSR.new(:csr => @csr)
      expect(csr.rsa?).to eq(true)
      expect(csr.ec?).to eq(false)
      expect(csr.dsa?).to eq(false)
    end
    it "returns RSA key algorithm for RSA CSR" do
      csr = R509::CSR.new(:csr => @csr)
      expect(csr.key_algorithm).to eq("RSA")
    end
  end

end
