require 'spec_helper'
require 'r509/config/subject_item_policy'
require 'r509/exceptions'

describe R509::Config::SubjectItemPolicy do
  it "raises an error if you supply a non-hash" do
    expect { R509::Config::SubjectItemPolicy.new('string') }.to raise_error(ArgumentError, "Must supply a hash in form 'shortname'=>hash_with_policy_info")
  end
  it "raises an error if you supply values that are not hashes as well" do
    expect { R509::Config::SubjectItemPolicy.new("CN" => "what what") }.to raise_error(ArgumentError, "Each value must be a hash with a :policy key")
  end
  it "raises an error if a required element is missing" do
    subject_item_policy = R509::Config::SubjectItemPolicy.new("CN" => { :policy => "required" }, "O" => { :policy => "required" }, "OU" => { :policy => "optional" }, "L" => { :policy => "required" })
    subject = R509::Subject.new [["CN", "langui.sh"], ["OU", "Org Unit"], ["O", "Org"]]
    expect { subject_item_policy.validate_subject(subject) }.to raise_error(R509::R509Error, /This profile requires you supply/)
  end
  it "raises an error if your hash values are anything other than required or optional" do
    expect { R509::Config::SubjectItemPolicy.new("CN" => { :policy => "somethirdoption" }) }.to raise_error(ArgumentError, "Unknown subject item policy value. Allowed values are required, optional, or match")
  end
  it "raises an error if a subject item does not match the value supplied" do
    subject_item_policy = R509::Config::SubjectItemPolicy.new("CN" => { :policy => "match", :value => "some-cn-goes-here" })
    subject = R509::Subject.new [["CN", "langui.sh"], ["OU", "Org Unit"], ["O", "Org"]]
    expect { subject_item_policy.validate_subject(subject) }.to raise_error(R509::R509Error, 'This profile requires that CN have value: some-cn-goes-here')
  end
  it "errors if you get case of subject_item_policy element wrong" do
    subject_item_policy = R509::Config::SubjectItemPolicy.new("cn" => { :policy => "required" })
    subject = R509::Subject.new [["CN", "langui.sh"]]
    expect { subject_item_policy.validate_subject(subject) }.to raise_error(R509::R509Error, 'This profile requires you supply cn')
  end
  it "validates a subject with the same fields as the policy" do
    subject_item_policy = R509::Config::SubjectItemPolicy.new("CN" => { :policy => "required" }, "O" => { :policy => "required" }, "OU" => { :policy => "optional" })
    subject = R509::Subject.new [["CN", "langui.sh"], ["OU", "Org Unit"], ["O", "Org"]]
    validated_subject = subject_item_policy.validate_subject(subject)
    expect(validated_subject.to_s).to eq(subject.to_s)
  end
  it "allows matched fields" do
    sip = R509::Config::SubjectItemPolicy.new("CN" => { :policy => "match", :value => "langui.sh" }, "O" => { :policy => "match", :value => "ooooor" })
    subject = R509::Subject.new [['CN', 'langui.sh'], ['O', 'ooooor']]
    validated_subject = sip.validate_subject(subject)
    expect(validated_subject.to_s).to eq(subject.to_s)
  end
  it "builds hash" do
    args = { "CN" => { :policy => "match", :value => "langui.sh" }, "O" => { :policy => "match", :value => "ooooor" } }
    sip = R509::Config::SubjectItemPolicy.new(args)
    # this equality check works because ruby does not compare hash order (which exists in 1.9+)
    # when doing comparison
    expect(sip.to_h).to eq(args)
  end
  it "builds yaml" do
    args = { "CN" => { :policy => "match", :value => "langui.sh" }, "O" => { :policy => "match", :value => "ooooor" } }
    sip = R509::Config::SubjectItemPolicy.new(args)
    # this equality check works because ruby does not compare hash order (which exists in 1.9+)
    # when doing comparison
    expect(YAML.load(sip.to_yaml)).to eq(args)
  end
  it "preserves subject order when applying policies" do
    subject_item_policy = R509::Config::SubjectItemPolicy.new("CN" => { :policy => "required" }, "O" => { :policy => "required" }, "OU" => { :policy => "optional" }, "L" => { :policy => "required" }, "C" => { :policy => "required" })
    subject = R509::Subject.new [["C", "US"], ["L", "Chicago"], ["ST", "Illinois"], ["CN", "langui.sh"], ["OU", "Org Unit"], ["O", "Org"]]
    validated_subject = subject_item_policy.validate_subject(subject)
    expect(validated_subject.to_s).to eq("/C=US/L=Chicago/CN=langui.sh/OU=Org Unit/O=Org")
  end
  it "removes subject items that are not in the policy" do
    subject_item_policy = R509::Config::SubjectItemPolicy.new("CN" => { :policy => "required" })
    subject = R509::Subject.new [["CN", "langui.sh"], ["OU", "Org Unit"], ["O", "Org"]]
    validated_subject = subject_item_policy.validate_subject(subject)
    expect(validated_subject.to_s).to eq("/CN=langui.sh")
  end
  it "does not reorder subject items as it validates" do
    subject_item_policy = R509::Config::SubjectItemPolicy.new("CN" => { :policy => "required" }, "O" => { :policy => "required" }, "OU" => { :policy => "optional" }, "L" => { :policy => "match", :value => "Chicago" })
    subject = R509::Subject.new [["L", "Chicago"], ["CN", "langui.sh"], ["OU", "Org Unit"], ["O", "Org"]]
    validated_subject = subject_item_policy.validate_subject(subject)
    expect(validated_subject.to_s).to eq(subject.to_s)
  end
  it "loads all the required, optional, and match elements" do
    subject_item_policy = R509::Config::SubjectItemPolicy.new("CN" => { :policy => "required" }, "O" => { :policy => "required" }, "OU" => { :policy => "optional" }, "L" => { :policy => "required" }, "emailAddress" => { :policy => "match", :value => "some@emailaddress.com" })
    expect(subject_item_policy.optional).to include("OU")
    expect(subject_item_policy.match).to include("emailAddress")
    expect(subject_item_policy.match_values["emailAddress"]).to eq("some@emailaddress.com")
    expect(subject_item_policy.required).to include("CN", "O", "L")
  end
end
