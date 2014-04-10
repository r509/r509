require 'spec_helper'

shared_examples_for "signing" do |selfsign|
  before :each do
    @options = {}
    @options[:csr] = @csr unless @csr.nil?
    @options[:spki] = @spki unless @spki.nil?
    if @options.key?(:spki)
      @options[:subject] = R509::Subject.new([['CN','test']])
    end
  end

  it "with default subject (selfsign:#{selfsign})" do
    if selfsign
      cert = R509::CertificateAuthority::Signer.selfsign(@options)
    else
      cert = @ca.sign(@options)
    end
    subject = (@options[:csr].nil?)?@options[:subject]:@options[:csr].subject
    cert.subject.to_s.should == subject.to_s
  end

  it "with specified subject (selfsign:#{selfsign})" do
    subject = R509::Subject.new
    subject.CN = 'myCN'
    subject.O = 'Org'
    @options[:subject] = subject
    if selfsign
      cert = R509::CertificateAuthority::Signer.selfsign(@options)
    else
      cert = @ca.sign(@options)
    end
    cert.subject.to_s.should == '/CN=myCN/O=Org'
  end

  it "with default md (selfsign:#{selfsign})" do
    cert = @ca.sign(@options)
    regex = Regexp.new(R509::MessageDigest::DEFAULT_MD,Regexp::IGNORECASE)
    cert.signature_algorithm.should match(regex)
  end

  it "with specified md (selfsign:#{selfsign})" do
    @options[:message_digest] = 'SHA256'
    if selfsign
      cert = R509::CertificateAuthority::Signer.selfsign(@options)
    else
      cert = @ca.sign(@options)
    end
    cert.signature_algorithm.should match(/sha256/i)
  end

  it "with no :extensions in options hash (selfsign:#{selfsign})" do
    if selfsign
      cert = R509::CertificateAuthority::Signer.selfsign(@options)
      size = 3
    else
      cert = @ca.sign(@options)
      size = 2
    end
    cert.extensions.size.should == size
  end

  it "with empty extensions array (selfsign:#{selfsign})" do
    @options[:extensions] = []
    if selfsign
      cert = R509::CertificateAuthority::Signer.selfsign(@options)
    else
      cert = @ca.sign(@options)
    end
    cert.extensions.size.should == 0
  end

  it "with multiple extensions (selfsign:#{selfsign})" do
    exts = []
    exts << R509::Cert::Extensions::BasicConstraints.new(:ca => false)
    exts << R509::Cert::Extensions::InhibitAnyPolicy.new(:value => 4)
    @options[:extensions] = exts
    if selfsign
      cert = R509::CertificateAuthority::Signer.selfsign(@options)
    else
      cert = @ca.sign(@options)
    end
    cert.extensions.size.should == 2
    cert.basic_constraints.is_ca?.should == false
    cert.inhibit_any_policy.value.should == 4
  end

  it "with random serial when serial is not specified and uses microtime as part of the serial to prevent collision (selfsign:#{selfsign})" do
    now = Time.now
    Time.stub(:now).and_return(now)
    time = now.to_i.to_s
    if selfsign
      cert = R509::CertificateAuthority::Signer.selfsign(@options)
    else
      cert = @ca.sign(@options)
    end
    cert.serial.to_s.size.should be >= 45
    cert.serial.to_s.index(time).should_not be_nil
  end

  it "with specified serial number (selfsign:#{selfsign})" do
    @options[:serial] = 11223344
    if selfsign
      cert = R509::CertificateAuthority::Signer.selfsign(@options)
    else
      cert = @ca.sign(@options)
    end
    cert.serial.should == 11223344
  end

  it "with default notBefore/notAfter dates (selfsign:#{selfsign})" do
    @options[:not_before] = (Time.now - (6 * 60 * 60)).utc
    @options[:not_after] = (Time.now - (6 * 60 * 60) + (365 * 24 * 60 * 60)).utc
    if selfsign
      cert = R509::CertificateAuthority::Signer.selfsign(@options)
    else
      cert = @ca.sign(@options)
    end
    cert.not_before.ctime.should == @options[:not_before].utc.ctime
    cert.not_after.ctime.should == @options[:not_after].utc.ctime
  end

  it "with specified notBefore/notAfter dates (selfsign:#{selfsign})" do
    @options[:not_before] = Time.now - 5 * 60 * 60
    @options[:not_after] = Time.now + 5 * 60 * 60
    if selfsign
      cert = R509::CertificateAuthority::Signer.selfsign(@options)
    else
      cert = @ca.sign(@options)
    end
    cert.not_before.ctime.should == @options[:not_before].utc.ctime
    cert.not_after.ctime.should == @options[:not_after].utc.ctime
  end

end

describe R509::CertificateAuthority::Signer do
  context "error handling" do
    before :each do
      test_ca_config = TestFixtures.test_ca_config
      @ca = R509::CertificateAuthority::Signer.new(test_ca_config)
    end

    it "raises error unless you provide a proper config (or nil)" do
      expect { R509::CertificateAuthority::Signer.new('invalid') }.to raise_error(R509::R509Error, 'config must be a kind of R509::Config::CAConfig')
    end

    it "raises an error if you don't pass csr or spki" do
      expect { @ca.sign({}) }.to raise_error(ArgumentError, "You must supply either :csr or :spki")
    end

    it "raises an error if you pass a config that has no private key for ca_cert" do
      config = R509::Config::CAConfig.new(:ca_cert => R509::Cert.new(:cert => TestFixtures::TEST_CA_CERT))
      expect { R509::CertificateAuthority::Signer.new(config) }.to raise_error(R509::R509Error, "You must have a private key associated with your CA certificate to issue")
    end

    it "raises an error if you pass both csr and spki" do
      csr = R509::CSR.new(:csr => TestFixtures::CSR)
      spki = R509::SPKI.new(:spki => TestFixtures::SPKI, :subject=>[['CN','test']])
      expect { @ca.sign(:spki => spki, :csr => csr) }.to raise_error(ArgumentError, "You can't pass both :csr and :spki")
    end

    it "raise an error if you don't pass an R509::SPKI in :spki" do
      spki = OpenSSL::Netscape::SPKI.new(TestFixtures::SPKI)
      expect { @ca.sign(:spki => spki) }.to raise_error(ArgumentError, 'You must pass an R509::SPKI object for :spki')
    end

    it "raise an error if you pass :spki without :subject" do
      spki = R509::SPKI.new(:spki => TestFixtures::SPKI)
      expect { @ca.sign(:spki => spki) }.to raise_error(ArgumentError, 'You must supply :subject when passing :spki')
    end

    it "raise an error if you don't pass an R509::CSR in :csr" do
      csr = OpenSSL::X509::Request.new(TestFixtures::CSR)
      expect { @ca.sign(:csr => csr) }.to raise_error(ArgumentError, 'You must pass an R509::CSR object for :csr')
    end

    it "raises an error if attempting to self-sign without a key" do
      csr = R509::CSR.new(:csr => TestFixtures::CSR)
      expect { R509::CertificateAuthority::Signer.selfsign(:csr => csr) }.to raise_error(ArgumentError, "CSR must also have a private key to self sign")
    end

    it "raises error when passing non-hash to selfsign method" do
      expect { R509::CertificateAuthority::Signer.selfsign(TestFixtures::CSR) }.to raise_error(ArgumentError, "You must pass a hash of options consisting of at minimum :csr")
    end

  end

  context "RSA CSR + CA" do
    before :all do
      test_ca_config = TestFixtures.test_ca_config
      @ca = R509::CertificateAuthority::Signer.new(test_ca_config)
      @csr = R509::CSR.new(:subject => [['C','US'],['ST','Illinois'],['L','Chicago'],['O','Paul Kehrer'],['CN','langui.sh']], :bit_strength => 1024)
    end

    it_validates "signing", false
    it_validates "signing", true # selfsign

    context "key in signed cert" do
      it "returns key when CSR contains key" do
        cert = R509::CertificateAuthority::Signer.selfsign(:csr => @csr)
        cert.key.should_not be_nil
        cert.key.should == @csr.key
        cert = @ca.sign(:csr => @csr)
        cert.key.should_not be_nil
        cert.key.should == @csr.key
      end
      it "does not return key when CSR has no key" do
        csr = R509::CSR.new(:csr => TestFixtures::CSR)
        cert = @ca.sign(:csr => csr)
        cert.key.should be_nil
      end
    end
  end

  context "RSA SPKI + CA" do
    before :all do
      test_ca_config = TestFixtures.test_ca_config
      @ca = R509::CertificateAuthority::Signer.new(test_ca_config)
      key = R509::PrivateKey.new(:bit_strength => 1024)
      @spki = R509::SPKI.new(:key => key)
    end

    it_validates "signing", false

    context "key in signed cert" do
      it "does not return key with SPKI" do
        cert = @ca.sign(:spki => @spki, :subject => R509::Subject.new(:CN => 'test'))
        cert.key.should be_nil
      end
    end
  end

  context "Elliptic Curve CSR + CA", :ec => true do
    before :all do
      test_ca_ec = R509::Config::CAConfig.from_yaml("test_ca_ec", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test_ec.yaml"), :ca_root_path => "#{File.dirname(__FILE__)}/../fixtures")
      @ca = R509::CertificateAuthority::Signer.new(test_ca_ec)
      @csr = R509::CSR.new(:subject => [['CN','elliptic curves']], :type => "ec")
    end

    it_validates "signing", false
    it_validates "signing", true # selfsign
  end

  context "Elliptic Curve SPKI + CA", :ec => true do
    before :all do
      test_ca_ec = R509::Config::CAConfig.from_yaml("test_ca_ec", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test_ec.yaml"), :ca_root_path => "#{File.dirname(__FILE__)}/../fixtures")
      @ca = R509::CertificateAuthority::Signer.new(test_ca_ec)
      private_key = R509::PrivateKey.new(:type => "ec")
      @spki = R509::SPKI.new(:key => private_key)
    end

    it_validates "signing", false
  end

  context "DSA CSR + CA", :ec => true do
    before :all do
      test_ca_dsa = R509::Config::CAConfig.from_yaml("test_ca_dsa", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test_dsa.yaml"), :ca_root_path => "#{File.dirname(__FILE__)}/../fixtures")

      @ca = R509::CertificateAuthority::Signer.new(test_ca_dsa)
      @csr = R509::CSR.new(:subject => [['CN','elliptic curves']], :type => "dsa", :bit_strength => 512)
    end

    it_validates "signing", false
    it_validates "signing", true # selfsign
  end

  context "DSA SPKI + CA", :ec => true do
    before :all do
      test_ca_dsa = R509::Config::CAConfig.from_yaml("test_ca_dsa", File.read("#{File.dirname(__FILE__)}/../fixtures/config_test_dsa.yaml"), :ca_root_path => "#{File.dirname(__FILE__)}/../fixtures")
      @ca = R509::CertificateAuthority::Signer.new(test_ca_dsa)
      private_key = R509::PrivateKey.new(:type => "dsa", :bit_strength => 512)
      @spki = R509::SPKI.new(:key => private_key)
    end

    it_validates "signing", false
  end
end
