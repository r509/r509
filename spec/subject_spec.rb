require 'spec_helper'
require 'r509/Subject'
require 'openssl'

describe R509::Subject do
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
        # we want the subject to be able to be one of two things, depending on how old your computer is
        # the "Be" matcher will call .include? on the array here because of be_include
        # does anyone know of a better, less stupid way to do this?
        ['/CN=common name/businessCategory=business category/L=locality/1.3.6.1.4.1.311.60.2.1.3=jurisdiction oid openssl typically does not know',"/CN=common name/2.5.4.15=business category/L=locality/1.3.6.1.4.1.311.60.2.1.3=jurisdiction oid openssl typically does not know"].should be_include subject.name.to_s
    end

end

