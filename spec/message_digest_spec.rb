require 'spec_helper'
require 'r509/message_digest'
require 'openssl'

describe R509::MessageDigest do
  it "translates sha1 name -> digest" do
    md = R509::MessageDigest.new("sha1")
    expect(md.name).to eq("sha1")
    expect(md.digest.is_a?(OpenSSL::Digest::SHA1)).to eq(true)
  end
  it "translates SHA1 name -> digest" do
    md = R509::MessageDigest.new("SHA1")
    expect(md.name).to eq("sha1")
    expect(md.digest.is_a?(OpenSSL::Digest::SHA1)).to eq(true)
  end
  it "translates sha224 name -> digest" do
    md = R509::MessageDigest.new("sha224")
    expect(md.name).to eq("sha224")
    expect(md.digest.is_a?(OpenSSL::Digest::SHA224)).to eq(true)
  end
  it "translates sha256 name -> digest" do
    md = R509::MessageDigest.new("sha256")
    expect(md.name).to eq("sha256")
    expect(md.digest.is_a?(OpenSSL::Digest::SHA256)).to eq(true)
  end
  it "translates SHA256 name -> digest" do
    md = R509::MessageDigest.new("SHA256")
    expect(md.name).to eq("sha256")
    expect(md.digest.is_a?(OpenSSL::Digest::SHA256)).to eq(true)
  end
  it "translates SHA384 name -> digest" do
    md = R509::MessageDigest.new("SHA384")
    expect(md.name).to eq("sha384")
    expect(md.digest.is_a?(OpenSSL::Digest::SHA384)).to eq(true)
  end
  it "translates sha512 name -> digest" do
    md = R509::MessageDigest.new("sha512")
    expect(md.name).to eq("sha512")
    expect(md.digest.is_a?(OpenSSL::Digest::SHA512)).to eq(true)
  end
  it "translates SHA512 name -> digest" do
    md = R509::MessageDigest.new("SHA512")
    expect(md.name).to eq("sha512")
    expect(md.digest.is_a?(OpenSSL::Digest::SHA512)).to eq(true)
  end
  it "translates md5 name -> digest" do
    md = R509::MessageDigest.new("md5")
    expect(md.name).to eq("md5")
    expect(md.digest.is_a?(OpenSSL::Digest::MD5)).to eq(true)
  end
  it "translates MD5 name -> digest" do
    md = R509::MessageDigest.new("MD5")
    expect(md.name).to eq("md5")
    expect(md.digest.is_a?(OpenSSL::Digest::MD5)).to eq(true)
  end
  it "translates dss1 name -> digest" do
    md = R509::MessageDigest.new("dss1")
    expect(md.name).to eq("dss1")
    expect(md.digest.is_a?(OpenSSL::Digest::DSS1)).to eq(true)
  end
  it "translates DSS1 name -> digest" do
    md = R509::MessageDigest.new("DSS1")
    expect(md.name).to eq("dss1")
    expect(md.digest.is_a?(OpenSSL::Digest::DSS1)).to eq(true)
  end
  it "translates unknown name -> digest" do
    md = R509::MessageDigest.new("unknown")
    expect(md.name).to eq("sha256")
    expect(md.digest.is_a?(OpenSSL::Digest::SHA256)).to eq(true)
  end
  it "translates sha1 digest -> name" do
    md = R509::MessageDigest.new(OpenSSL::Digest::SHA1.new)
    expect(md.name).to eq("sha1")
    expect(md.digest.is_a?(OpenSSL::Digest::SHA1)).to eq(true)
  end
  it "translates sha224 digest -> name" do
    md = R509::MessageDigest.new(OpenSSL::Digest::SHA224.new)
    expect(md.name).to eq("sha224")
    expect(md.digest.is_a?(OpenSSL::Digest::SHA224)).to eq(true)
  end
  it "translates sha256 digest -> name" do
    md = R509::MessageDigest.new(OpenSSL::Digest::SHA256.new)
    expect(md.name).to eq("sha256")
    expect(md.digest.is_a?(OpenSSL::Digest::SHA256)).to eq(true)
  end
  it "translates sha384 digest -> name" do
    md = R509::MessageDigest.new(OpenSSL::Digest::SHA384.new)
    expect(md.name).to eq("sha384")
    expect(md.digest.is_a?(OpenSSL::Digest::SHA384)).to eq(true)
  end
  it "translates sha512 digest -> name" do
    md = R509::MessageDigest.new(OpenSSL::Digest::SHA512.new)
    expect(md.name).to eq("sha512")
    expect(md.digest.is_a?(OpenSSL::Digest::SHA512)).to eq(true)
  end
  it "translates md5 digest -> name" do
    md = R509::MessageDigest.new(OpenSSL::Digest::MD5.new)
    expect(md.name).to eq("md5")
    expect(md.digest.is_a?(OpenSSL::Digest::MD5)).to eq(true)
  end
  it "translates dss1 digest -> name" do
    md = R509::MessageDigest.new(OpenSSL::Digest::DSS1.new)
    expect(md.name).to eq("dss1")
    expect(md.digest.is_a?(OpenSSL::Digest::DSS1)).to eq(true)
  end
  it "creates a default digest with no params or nil" do
    md = R509::MessageDigest.new
    expect(md.name).to eq(R509::MessageDigest::DEFAULT_MD.downcase)
    md = R509::MessageDigest.new(nil)
    expect(md.name).to eq(R509::MessageDigest::DEFAULT_MD.downcase)
  end
  it "exception on unknown digest -> name" do
    expect { R509::MessageDigest.new(12345) }.to raise_error(ArgumentError)
  end
end
