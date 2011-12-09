require 'spec_helper'
require 'r509/MessageDigest'
require 'openssl'

describe R509::MessageDigest do
    it "translates sha1 name -> digest" do
        md = R509::MessageDigest.new("sha1")
        md.name.should == "sha1"
        md.digest.kind_of?(OpenSSL::Digest::SHA1).should == true
    end
    it "translates SHA1 name -> digest" do
        md = R509::MessageDigest.new("SHA1")
        md.name.should == "sha1"
        md.digest.kind_of?(OpenSSL::Digest::SHA1).should == true
    end
    it "translates sha256 name -> digest" do
        md = R509::MessageDigest.new("sha256")
        md.name.should == "sha256"
        md.digest.kind_of?(OpenSSL::Digest::SHA256).should == true
    end
    it "translates SHA256 name -> digest" do
        md = R509::MessageDigest.new("SHA256")
        md.name.should == "sha256"
        md.digest.kind_of?(OpenSSL::Digest::SHA256).should == true
    end
    it "translates sha512 name -> digest" do
        md = R509::MessageDigest.new("sha512")
        md.name.should == "sha512"
        md.digest.kind_of?(OpenSSL::Digest::SHA512).should == true
    end
    it "translates SHA512 name -> digest" do
        md = R509::MessageDigest.new("SHA512")
        md.name.should == "sha512"
        md.digest.kind_of?(OpenSSL::Digest::SHA512).should == true
    end
    it "translates md5 name -> digest" do
        md = R509::MessageDigest.new("md5")
        md.name.should == "md5"
        md.digest.kind_of?(OpenSSL::Digest::MD5).should == true
    end
    it "translates MD5 name -> digest" do
        md = R509::MessageDigest.new("MD5")
        md.name.should == "md5"
        md.digest.kind_of?(OpenSSL::Digest::MD5).should == true
    end
    it "translates dss1 name -> digest" do
        md = R509::MessageDigest.new("dss1")
        md.name.should == "dss1"
        md.digest.kind_of?(OpenSSL::Digest::DSS1).should == true
    end
    it "translates DSS1 name -> digest" do
        md = R509::MessageDigest.new("DSS1")
        md.name.should == "dss1"
        md.digest.kind_of?(OpenSSL::Digest::DSS1).should == true
    end
    it "translates unknown name -> digest" do
        md = R509::MessageDigest.new("unknown")
        md.name.should == "sha1"
        md.digest.kind_of?(OpenSSL::Digest::SHA1).should == true
    end
    it "translates sha1 digest -> name" do
        md = R509::MessageDigest.new(OpenSSL::Digest::SHA1.new)
        md.name.should == "sha1"
        md.digest.kind_of?(OpenSSL::Digest::SHA1).should == true
    end
    it "translates sha256 digest -> name" do
        md = R509::MessageDigest.new(OpenSSL::Digest::SHA256.new)
        md.name.should == "sha256"
        md.digest.kind_of?(OpenSSL::Digest::SHA256).should == true
    end
    it "translates sha512 digest -> name" do
        md = R509::MessageDigest.new(OpenSSL::Digest::SHA512.new)
        md.name.should == "sha512"
        md.digest.kind_of?(OpenSSL::Digest::SHA512).should == true
    end
    it "translates md5 digest -> name" do
        md = R509::MessageDigest.new(OpenSSL::Digest::MD5.new)
        md.name.should == "md5"
        md.digest.kind_of?(OpenSSL::Digest::MD5).should == true
    end
    it "translates dss1 digest -> name" do
        md = R509::MessageDigest.new(OpenSSL::Digest::DSS1.new)
        md.name.should == "dss1"
        md.digest.kind_of?(OpenSSL::Digest::DSS1).should == true
    end
    it "exception on unknown digest -> name" do
        expect{ R509::MessageDigest.new(12345) }.to raise_error(ArgumentError)
    end
end
