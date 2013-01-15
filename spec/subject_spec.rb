require 'spec_helper'
require 'r509/subject'
require 'openssl'

describe R509::Subject do
  before :all do
    @csr_unknown_oid = TestFixtures::CSR_UNKNOWN_OID
  end

  it "initializes an empty subject and gets the name" do
    subject = R509::Subject.new
    subject.name.to_s.should == ""
  end
  it "initializes an empty subject, adds a field, and gets the name" do
    subject = R509::Subject.new
    subject["CN"] = "domain.com"
    subject.name.to_s.should == "/CN=domain.com"
  end
  it "initializes with a subject array, and gets the name" do
    subject = R509::Subject.new([["CN", "domain.com"], ["O", "my org"]])
    subject.name.to_s.should == "/CN=domain.com/O=my org"
  end
  it "initializes with a name, gets the name" do
    name = OpenSSL::X509::Name.new([["CN", "domain.com"], ["O", "my org"], ["OU", "my unit"]])
    subject = R509::Subject.new(name)
    subject.name.to_s.should == "/CN=domain.com/O=my org/OU=my unit"
  end
  it "initializes with a subject" do
    s1 = R509::Subject.new
    s1["CN"] = "domain.com"
    s1["O"] = "my org"

    s2 = R509::Subject.new(s1)
    s2.name.to_s.should == s1.name.to_s
  end
  it "preserves order of a full subject line" do
    subject = R509::Subject.new([['CN','langui.sh'],['ST','Illinois'],['L','Chicago'],['C','US'],['emailAddress','ca@langui.sh']])
    subject.name.to_s.should == '/CN=langui.sh/ST=Illinois/L=Chicago/C=US/emailAddress=ca@langui.sh'
  end
  it "preserves order of a full subject line and uses to_s directly" do
    subject = R509::Subject.new([['CN','langui.sh'],['ST','Illinois'],['L','Chicago'],['C','US'],['emailAddress','ca@langui.sh']])
    subject.to_s.should == '/CN=langui.sh/ST=Illinois/L=Chicago/C=US/emailAddress=ca@langui.sh'
  end
  it "preserves order with raw OIDs, and potentially fills in known OID names" do
    subject = R509::Subject.new([['2.5.4.3','common name'],['2.5.4.15','business category'],['2.5.4.7','locality'],['1.3.6.1.4.1.311.60.2.1.3','jurisdiction oid openssl typically does not know']])
    subject.to_s.should == "/CN=common name/businessCategory=business category/L=locality/jurisdictionOfIncorporationCountryName=jurisdiction oid openssl typically does not know"
  end

  it "edits an existing subject entry" do
    subject = R509::Subject.new([["CN", "domain1.com"], ["O", "my org"]])
    subject.to_s.should == "/CN=domain1.com/O=my org"

    subject["CN"] = "domain2.com"
    subject.to_s.should == "/CN=domain2.com/O=my org"
  end

  it "deletes an existing subject entry" do
    subject = R509::Subject.new([["CN", "domain1.com"], ["O", "my org"]])
    subject.to_s.should == "/CN=domain1.com/O=my org"

    subject.delete("CN")
    subject.to_s.should == "/O=my org"
  end

  it "is empty when initialized" do
    subject = R509::Subject.new
    subject.empty?.should == true
    subject["CN"] = "domain.com"
    subject.empty?.should == false
  end

  it "is not empty" do
    subject = R509::Subject.new([["CN", "domain1.com"]])
    subject.empty?.should == false
  end

  it "can get a component out of the subject" do
    subject = R509::Subject.new([["CN", "domain.com"]])
    subject["CN"].should == "domain.com"
    subject["O"].should == nil
  end

  it "adds an OID" do
    subject = R509::Subject.new
    subject['1.3.6.1.4.1.311.60.2.1.3'] = 'jurisdiction oid openssl typically does not know'
    subject['1.3.6.1.4.1.311.60.2.1.3'].should == 'jurisdiction oid openssl typically does not know'
  end

  it "deletes an OID" do
    subject = R509::Subject.new([["CN", "domain.com"], ['1.3.6.1.4.1.38383.60.2.1.0.0', 'random oid']])
    subject.to_s.should == "/CN=domain.com/1.3.6.1.4.1.38383.60.2.1.0.0=random oid"
    subject.delete("1.3.6.1.4.1.38383.60.2.1.0.0")
    subject.to_s.should == "/CN=domain.com"
  end

  it "fails when you instantiate with an unknown shortname" do
    expect { R509::Subject.new([["NOTRIGHT", "foo"]]) }.to raise_error(OpenSSL::X509::NameError)
  end

  it "fails when you add an unknown shortname" do
    subject = R509::Subject.new
    expect { subject["WRONG"] = "bar" }.to raise_error(OpenSSL::X509::NameError)
  end

  it "parses unknown OIDs out of a CSR" do
    csr = R509::Csr.new(:csr => @csr_unknown_oid)
    subject = R509::Subject.new(csr.subject)
    subject["1.2.3.4.5.6.7.8.9.8.7.6.5.4.3.2.1.0.0"].should == "random oid!"
    subject["1.3.3.543.567.32.43.335.1.1.1"].should == "another random oid!"
    subject["CN"].should == 'normaldomain.com'
  end

end

describe R509::NameSanitizer do
  before :all do
    @sanitizer = R509::NameSanitizer.new
  end

  it "when it has only known OIDs" do
    name = OpenSSL::X509::Name.new [["C", "US"], ["ST", "Illinois"]]
    array = @sanitizer.sanitize(name)
    array.size.should == 2
    array[0][0].should == "C"
    array[0][1].should == "US"
    array[1][0].should == "ST"
    array[1][1].should == "Illinois"
  end

  it "when it has only unknown OIDs" do
    name = OpenSSL::X509::Name.new [["1.2.3.4", "US"], ["1.2.3.5", "Illinois"]]
    array = @sanitizer.sanitize(name)
    array.size.should == 2
    array[0][0].should == "1.2.3.4"
    array[0][1].should == "US"
    array[1][0].should == "1.2.3.5"
    array[1][1].should == "Illinois"
  end

  it "when it has an unknown between two knowns" do
    name = OpenSSL::X509::Name.new [["CN", "domain.com"], ["1.2.3.4", "US"], ["ST", "Illinois"]]
    array = @sanitizer.sanitize(name)
    array.size.should == 3
    array[0][0].should == "CN"
    array[0][1].should == "domain.com"
    array[1][0].should == "1.2.3.4"
    array[1][1].should == "US"
    array[2][0].should == "ST"
    array[2][1].should == "Illinois"
  end

  it "when it has a known between two unknowns" do
    name = OpenSSL::X509::Name.new [["1.2.3.4", "domain.com"], ["C", "US"], ["1.2.3.5", "Illinois"]]
    array = @sanitizer.sanitize(name)
    array.size.should == 3
    array[0][0].should == "1.2.3.4"
    array[0][1].should == "domain.com"
    array[1][0].should == "C"
    array[1][1].should == "US"
    array[2][0].should == "1.2.3.5"
    array[2][1].should == "Illinois"
  end

  it "when a known has the same value as an unknown defined before it" do
    name = OpenSSL::X509::Name.new [["1.2.3.4", "domain.com"], ["CN", "domain.com"]]
    array = @sanitizer.sanitize(name)
    array.size.should == 2
    array[0][0].should == "1.2.3.4"
    array[0][1].should == "domain.com"
    array[1][0].should == "CN"
    array[1][1].should == "domain.com"
  end

  it "when two unknowns have the same value" do
    name = OpenSSL::X509::Name.new [["1.2.3.4", "domain.com"], ["1.2.3.5", "domain.com"]]
    array = @sanitizer.sanitize(name)
    array.size.should == 2
    array[0][0].should == "1.2.3.4"
    array[0][1].should == "domain.com"
    array[1][0].should == "1.2.3.5"
    array[1][1].should == "domain.com"
  end

  it "when two unknowns have the same oid and different values" do
    name = OpenSSL::X509::Name.new [["1.2.3.4", "domain.com"], ["1.2.3.4", "other"]]
    array = @sanitizer.sanitize(name)
    array.size.should == 2
    array[0][0].should == "1.2.3.4"
    array[0][1].should == "domain.com"
    array[1][0].should == "1.2.3.4"
    array[1][1].should == "other"
  end

  it "when two unknowns have the same oid and the same value" do
    name = OpenSSL::X509::Name.new [["1.2.3.4", "domain.com"], ["1.2.3.4", "domain.com"]]
    array = @sanitizer.sanitize(name)
    array.size.should == 2
    array[0][0].should == "1.2.3.4"
    array[0][1].should == "domain.com"
    array[1][0].should == "1.2.3.4"
    array[1][1].should == "domain.com"
  end
end
