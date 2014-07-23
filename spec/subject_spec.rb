require 'spec_helper'
require 'r509/subject'
require 'openssl'

describe R509::Subject do
  before :all do
    @csr_unknown_oid = TestFixtures::CSR_UNKNOWN_OID
  end

  it "initializes an empty subject and gets the name" do
    subject = R509::Subject.new
    expect(subject.name.to_s).to eq("")
  end
  it "initializes an empty subject, adds a field, and gets the name" do
    subject = R509::Subject.new
    subject["CN"] = "domain.com"
    expect(subject.name.to_s).to eq("/CN=domain.com")
  end
  it "initializes with a subject array, and gets the name" do
    subject = R509::Subject.new([["CN", "domain.com"], ["O", "my org"]])
    expect(subject.name.to_s).to eq("/CN=domain.com/O=my org")
  end
  it "initializes with a subject hash, and gets the name" do
    subject = R509::Subject.new(:CN => "domain.com", :O => "my org", :"1.2.3.4.4.5.6.7" => "what")
    expect(subject.name.to_s).to eq("/CN=domain.com/O=my org/1.2.3.4.4.5.6.7=what")
  end
  it "initializes with a name, gets the name" do
    name = OpenSSL::X509::Name.new([["CN", "domain.com"], ["O", "my org"], ["OU", "my unit"]])
    subject = R509::Subject.new(name)
    expect(subject.name.to_s).to eq("/CN=domain.com/O=my org/OU=my unit")
  end
  it "initializes with a subject" do
    s1 = R509::Subject.new
    s1["CN"] = "domain.com"
    s1["O"] = "my org"

    s2 = R509::Subject.new(s1)
    expect(s2.name.to_s).to eq(s1.name.to_s)
  end
  it "preserves order of a full subject line" do
    subject = R509::Subject.new([['CN', 'langui.sh'], ['ST', 'Illinois'], ['L', 'Chicago'], ['C', 'US'], ['emailAddress', 'ca@langui.sh']])
    expect(subject.name.to_s).to eq('/CN=langui.sh/ST=Illinois/L=Chicago/C=US/emailAddress=ca@langui.sh')
  end
  it "preserves order of a full subject line and uses to_s directly" do
    subject = R509::Subject.new([['CN', 'langui.sh'], ['ST', 'Illinois'], ['L', 'Chicago'], ['C', 'US'], ['emailAddress', 'ca@langui.sh']])
    expect(subject.to_s).to eq('/CN=langui.sh/ST=Illinois/L=Chicago/C=US/emailAddress=ca@langui.sh')
  end
  it "preserves order with raw OIDs, and potentially fills in known OID names" do
    subject = R509::Subject.new([['2.5.4.3', 'common name'], ['2.5.4.15', 'business category'], ['2.5.4.7', 'locality'], ['1.3.6.1.4.1.311.60.2.1.3', 'jurisdiction oid openssl typically does not know']])
    expect(subject.to_s).to eq("/CN=common name/businessCategory=business category/L=locality/jurisdictionOfIncorporationCountryName=jurisdiction oid openssl typically does not know")
  end

  it "edits an existing subject entry" do
    subject = R509::Subject.new([["CN", "domain1.com"], ["O", "my org"]])
    expect(subject.to_s).to eq("/CN=domain1.com/O=my org")

    subject["CN"] = "domain2.com"
    expect(subject.to_s).to eq("/CN=domain2.com/O=my org")
  end

  it "deletes an existing subject entry" do
    subject = R509::Subject.new([["CN", "domain1.com"], ["O", "my org"]])
    expect(subject.to_s).to eq("/CN=domain1.com/O=my org")

    subject.delete("CN")
    expect(subject.to_s).to eq("/O=my org")
  end

  it "is empty when initialized" do
    subject = R509::Subject.new
    expect(subject.empty?).to eq(true)
    subject["CN"] = "domain.com"
    expect(subject.empty?).to eq(false)
  end

  it "is not empty" do
    subject = R509::Subject.new([["CN", "domain1.com"]])
    expect(subject.empty?).to eq(false)
  end

  it "can get a component out of the subject" do
    subject = R509::Subject.new([["CN", "domain.com"]])
    expect(subject["CN"]).to eq("domain.com")
    expect(subject["O"]).to be_nil
  end

  it "adds an OID" do
    subject = R509::Subject.new
    subject['1.3.6.1.4.1.311.60.2.1.3'] = 'jurisdiction oid openssl typically does not know'
    expect(subject['1.3.6.1.4.1.311.60.2.1.3']).to eq('jurisdiction oid openssl typically does not know')
  end

  it "deletes an OID" do
    subject = R509::Subject.new([["CN", "domain.com"], ['1.3.6.1.4.1.38383.60.2.1.0.0', 'random oid']])
    expect(subject.to_s).to eq("/CN=domain.com/1.3.6.1.4.1.38383.60.2.1.0.0=random oid")
    subject.delete("1.3.6.1.4.1.38383.60.2.1.0.0")
    expect(subject.to_s).to eq("/CN=domain.com")
  end

  it "fails when you instantiate with an unknown shortname" do
    expect { R509::Subject.new([["NOTRIGHT", "foo"]]) }.to raise_error(OpenSSL::X509::NameError)
  end

  it "fails when you add an unknown shortname" do
    subject = R509::Subject.new
    expect { subject["WRONG"] = "bar" }.to raise_error(OpenSSL::X509::NameError)
  end

  it "parses unknown OIDs out of a CSR" do
    csr = R509::CSR.new(:csr => @csr_unknown_oid)
    subject = R509::Subject.new(csr.subject)
    expect(subject["1.2.3.4.5.6.7.8.9.8.7.6.5.4.3.2.1.0.0"]).to eq("random oid!")
    expect(subject["1.3.3.543.567.32.43.335.1.1.1"]).to eq("another random oid!")
    expect(subject["CN"]).to eq('normaldomain.com')
  end

  it "builds a hash" do
    args = { :CN => "domain.com", :O => "my org", :"1.2.3.4.4.5.6.7" => "what" }
    subject = R509::Subject.new(args)
    expect(subject.to_h).to eq(args)
  end

  it "builds yaml" do
    args = { :CN => "domain.com", :O => "my org", :"1.2.3.4.4.5.6.7" => "what" }
    subject = R509::Subject.new(args)
    expect(YAML.load(subject.to_yaml)).to eq(args)
  end

  context "dynamic getter/setter behaviors" do
    it "recognizes getters for a standard subject oid" do
      subject = R509::Subject.new [['CN', 'testCN']]
      expect(subject.CN).to eq('testCN')
      expect(subject.common_name).to eq('testCN')
      expect(subject.commonName).to eq('testCN')
    end

    it "recognizes setters for a standard subject oid" do
      subject = R509::Subject.new
      subject.CN = 'testCN'
      expect(subject.CN).to eq('testCN')
      subject.common_name = 'testCN2'
      expect(subject.common_name).to eq('testCN2')
      subject.commonName = 'testCN3'
      expect(subject.commonName).to eq('testCN3')
      expect(subject.CN).to eq('testCN3')
      expect(subject.common_name).to eq('testCN3')
    end

    it "returns properly for respond_to? with a standard subject oid" do
      subject = R509::Subject.new
      expect(subject.respond_to?("CN")).to eq(true)
      expect(subject.respond_to?("CN=")).to eq(true)
      expect(subject.respond_to?("commonName")).to eq(true)
      expect(subject.respond_to?("commonName=")).to eq(true)
      expect(subject.respond_to?("common_name")).to eq(true)
      expect(subject.respond_to?("common_name=")).to eq(true)
    end

    it "returns properly for respond_to? for an invalid method name" do
      subject = R509::Subject.new
      expect(subject.respond_to?("not_a_real_method=")).to eq(false)
      expect(subject.respond_to?("not_a_real_method")).to eq(false)
    end

    it "errors on invalid method names" do
      subject = R509::Subject.new
      expect { subject.random_value = "assign" }.to raise_error(NoMethodError)
      expect { subject.random_value }.to raise_error(NoMethodError)
    end

    it "works with an arbitrarily defined OID" do
      R509::OIDMapper.register("1.4.3.2.1.2.3.6.6.6.6", "AOI", "arbitraryName")
      subject = R509::Subject.new
      subject.AOI = "test"
      expect(subject.AOI).to eq("test")
      subject.arbitrary_name = "test2"
      expect(subject.arbitrary_name).to eq("test2")
      subject.arbitraryName = "test3"
      expect(subject.arbitraryName).to eq("test3")
      expect(subject.AOI).to eq("test3")
      expect(subject.arbitrary_name).to eq("test3")
    end

    it "returns properly for respond_to? with a custom subject oid" do
      R509::OIDMapper.register("1.4.3.2.1.2.3.7.7.7.7", "IOS", "iOperatingSystem")
      subject = R509::Subject.new
      expect(subject.respond_to?("IOS")).to eq(true)
      expect(subject.respond_to?("IOS=")).to eq(true)
      expect(subject.respond_to?("iOperatingSystem")).to eq(true)
      expect(subject.respond_to?("iOperatingSystem=")).to eq(true)
      expect(subject.respond_to?("i_operating_system")).to eq(true)
      expect(subject.respond_to?("i_operating_system=")).to eq(true)
    end

  end

end

describe R509::NameSanitizer do
  before :all do
    @sanitizer = R509::NameSanitizer.new
  end

  it "when it has only known OIDs" do
    name = OpenSSL::X509::Name.new [["C", "US"], ["ST", "Illinois"]]
    array = @sanitizer.sanitize(name)
    expect(array.size).to eq(2)
    expect(array[0][0]).to eq("C")
    expect(array[0][1]).to eq("US")
    expect(array[1][0]).to eq("ST")
    expect(array[1][1]).to eq("Illinois")
  end

  it "when it has only unknown OIDs" do
    name = OpenSSL::X509::Name.new [["1.2.3.4", "US"], ["1.2.3.5", "Illinois"]]
    array = @sanitizer.sanitize(name)
    expect(array.size).to eq(2)
    expect(array[0][0]).to eq("1.2.3.4")
    expect(array[0][1]).to eq("US")
    expect(array[1][0]).to eq("1.2.3.5")
    expect(array[1][1]).to eq("Illinois")
  end

  it "when it has an unknown between two knowns" do
    name = OpenSSL::X509::Name.new [["CN", "domain.com"], ["1.2.3.4", "US"], ["ST", "Illinois"]]
    array = @sanitizer.sanitize(name)
    expect(array.size).to eq(3)
    expect(array[0][0]).to eq("CN")
    expect(array[0][1]).to eq("domain.com")
    expect(array[1][0]).to eq("1.2.3.4")
    expect(array[1][1]).to eq("US")
    expect(array[2][0]).to eq("ST")
    expect(array[2][1]).to eq("Illinois")
  end

  it "when it has a known between two unknowns" do
    name = OpenSSL::X509::Name.new [["1.2.3.4", "domain.com"], ["C", "US"], ["1.2.3.5", "Illinois"]]
    array = @sanitizer.sanitize(name)
    expect(array.size).to eq(3)
    expect(array[0][0]).to eq("1.2.3.4")
    expect(array[0][1]).to eq("domain.com")
    expect(array[1][0]).to eq("C")
    expect(array[1][1]).to eq("US")
    expect(array[2][0]).to eq("1.2.3.5")
    expect(array[2][1]).to eq("Illinois")
  end

  it "when a known has the same value as an unknown defined before it" do
    name = OpenSSL::X509::Name.new [["1.2.3.4", "domain.com"], ["CN", "domain.com"]]
    array = @sanitizer.sanitize(name)
    expect(array.size).to eq(2)
    expect(array[0][0]).to eq("1.2.3.4")
    expect(array[0][1]).to eq("domain.com")
    expect(array[1][0]).to eq("CN")
    expect(array[1][1]).to eq("domain.com")
  end

  it "when two unknowns have the same value" do
    name = OpenSSL::X509::Name.new [["1.2.3.4", "domain.com"], ["1.2.3.5", "domain.com"]]
    array = @sanitizer.sanitize(name)
    expect(array.size).to eq(2)
    expect(array[0][0]).to eq("1.2.3.4")
    expect(array[0][1]).to eq("domain.com")
    expect(array[1][0]).to eq("1.2.3.5")
    expect(array[1][1]).to eq("domain.com")
  end

  it "when two unknowns have the same oid and different values" do
    name = OpenSSL::X509::Name.new [["1.2.3.4", "domain.com"], ["1.2.3.4", "other"]]
    array = @sanitizer.sanitize(name)
    expect(array.size).to eq(2)
    expect(array[0][0]).to eq("1.2.3.4")
    expect(array[0][1]).to eq("domain.com")
    expect(array[1][0]).to eq("1.2.3.4")
    expect(array[1][1]).to eq("other")
  end

  it "when two unknowns have the same oid and the same value" do
    name = OpenSSL::X509::Name.new [["1.2.3.4", "domain.com"], ["1.2.3.4", "domain.com"]]
    array = @sanitizer.sanitize(name)
    expect(array.size).to eq(2)
    expect(array[0][0]).to eq("1.2.3.4")
    expect(array[0][1]).to eq("domain.com")
    expect(array[1][0]).to eq("1.2.3.4")
    expect(array[1][1]).to eq("domain.com")
  end
end
