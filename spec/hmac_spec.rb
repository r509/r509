require 'spec_helper'
require 'r509/hmac'
require 'openssl'

describe R509::HMAC do
  before :all do
    @valid_hmacsha512_key = "\xEB\x88\x9B\n\x9E\x05\tHk\x12\xCF\xAF\xA3\xD8kMX4\xA4\xE8\xB3\xC6\xC07km\b\x13\x052\xE2\xCC{\xCC/}\xA18\xBE\xA3IE\x814\x96\x8A\x99\xF3\x93\xB7{\xE0$\xE2\b\x174\xDD}'\x15\xB4Q\xA7"
    @valid_hmacsha1_key = "l\xFA\x94}\x93[a\xBD\"W\tO\x17b\x88\xF6\t\x9128"
    @hmacsha512_sig = TestFixtures::HMACSHA512_SIG
    @hmacsha1_sig = TestFixtures::HMACSHA1_SIG
  end

  it "errors when no hash is supplied" do
    expect { R509::HMAC.hexdigest('wrong pararm') }.to raise_error(ArgumentError, 'Must provide a hash of options')
    expect { R509::HMAC.digest('wrong pararm') }.to raise_error(ArgumentError, 'Must provide a hash of options')
  end

  it "errors when no key is supplied" do
    expect { R509::HMAC.hexdigest(:data => 'hmac me!') }.to raise_error(ArgumentError, ':key is required')
    expect { R509::HMAC.digest(:data => 'hmac me!') }.to raise_error(ArgumentError, ':key is required')
    expect { R509::HMAC.hexdigest(:key => '', :data => 'hmac me!') }.to raise_error(ArgumentError, ':key is required')
    expect { R509::HMAC.digest(:key => '', :data => 'hmac me!') }.to raise_error(ArgumentError, ':key is required')
  end

  it "errors when no data is supplied" do
    expect { R509::HMAC.hexdigest(:key => @valid_hmacsha512_key) }.to raise_error(ArgumentError, ':data is required')
    expect { R509::HMAC.digest(:key => @valid_hmacsha512_key) }.to raise_error(ArgumentError, ':data is required')
    expect { R509::HMAC.hexdigest(:key => @valid_hmacsha512_key, :data => '') }.to raise_error(ArgumentError, ':data is required')
    expect { R509::HMAC.digest(:key => @valid_hmacsha512_key, :data => '') }.to raise_error(ArgumentError, ':data is required')
  end

  it "errors when key is too short" do
    key = "worthless key"
    expect { R509::HMAC.hexdigest(:key => key, :data => 'hmac me!') }.to raise_error(R509::R509Error, 'Key must be at least equal to the digest length. Since your digest is sha512 the length must be 64 bytes. This check can be overridden with :allow_low_entropy if needed')
    expect { R509::HMAC.digest(:key => key, :data => 'hmac me!') }.to raise_error(R509::R509Error, 'Key must be at least equal to the digest length. Since your digest is sha512 the length must be 64 bytes. This check can be overridden with :allow_low_entropy if needed')
  end

  it "allows keys that are too short with :allow_low_entropy" do
    key = "worthless key"
    expect { R509::HMAC.hexdigest(:key => key, :data => 'hmac me!', :allow_low_entropy => true) }.to_not raise_error
    expect { R509::HMAC.digest(:key => key, :data => 'hmac me!', :allow_low_entropy => true) }.to_not raise_error
  end

  it "responds successfully when the params are valid for the default digest" do
    R509::HMAC.hexdigest(:key => @valid_hmacsha512_key, :data => 'sign me!').should == '9eecc06cbc3dc413a5d531853b2b669fd3331b811ebd6cbd91ffdd6ad3598e0313cc54346dfde5bbaeb1e41b222514115eceed6f0c7a567a28f0de2b101be0c7'

    R509::HMAC.digest(:key => @valid_hmacsha512_key, :data => 'sign me!').should == @hmacsha512_sig
  end

  it "responds successfully when the params are valid for a custom digest" do
    R509::HMAC.hexdigest(:message_digest => 'sha1', :key => @valid_hmacsha1_key, :data => 'sign me!').should == "f8857d44bbe5afa1407bb8c247c319c85a60262a"
    R509::HMAC.digest(:message_digest => 'sha1', :key => @valid_hmacsha1_key, :data => 'sign me!').should == @hmacsha1_sig
  end

  it "generates a key with the proper length for the default digest (sha512)" do
    R509::HMAC.generate_key.size.should == 64
  end

  it "generates a key with the proper length for a custom digest" do
    R509::HMAC.generate_key('sha1').size.should == 20
    R509::HMAC.generate_key('sha256').size.should == 32
  end

  it "rejects keys with shannon entropy < 3.5" do
    expect { R509::HMAC.hexdigest(:key => "key00000000000000000", :message_digest => 'sha1', :data => 'boo!') }.to raise_error(R509::R509Error,"The shannon entropy of this key is low and therefore is not considered secure. Consider using a key from the R509::HMAC.generate_key method. This check can be overridden with :allow_low_entropy if needed")
    expect { R509::HMAC.digest(:key => "key00000000000000000", :message_digest => 'sha1', :data => 'boo!') }.to raise_error(R509::R509Error,"The shannon entropy of this key is low and therefore is not considered secure. Consider using a key from the R509::HMAC.generate_key method. This check can be overridden with :allow_low_entropy if needed")
  end

  it "allows keys with shannon entropy < 3.5 with :allow_low_entropy" do
    expect { R509::HMAC.hexdigest(:key => "key00000000000000000", :allow_low_entropy => true, :message_digest => 'sha1', :data => 'boo!') }.to_not raise_error
    expect { R509::HMAC.digest(:key => "key00000000000000000", :allow_low_entropy => true, :message_digest => 'sha1', :data => 'boo!') }.to_not raise_error
  end

  it "allows keys with shannon entropy > 3.5" do
    just_barely_allowed_key = 'mko09ijnbhu87yffffff'
    expect { R509::HMAC.hexdigest(:key => just_barely_allowed_key, :message_digest => 'sha1', :data => 'allowed!') }.to_not raise_error
  end

end
