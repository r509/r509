require 'spec_helper'

def capture_stdout
  original_stdout = $stdout
  $stdout = fake = StringIO.new
  begin
    yield
  ensure
    $stdout = original_stdout
  end
  fake.string
end

describe R509 do
  it "prints version and feature info with ::print_debug" do
    output = capture_stdout { R509.print_debug }
    expect(output).to match(/^r509 v/)
    expect(output).to match(/^OpenSSL/)
    expect(output).to match(/^Ruby/)
    expect(output).to match(/^Elliptic/)
  end
  it "checks if ec is supported", :ec => true do
    expect(R509.ec_supported?).to eq(true)
  end
  it "checks if EC is unsupported" do
    ec = OpenSSL::PKey.send(:remove_const, :EC) # remove EC support for test!
    load('r509/openssl/ec-hack.rb')
    expect(R509.ec_supported?).to eq(false)
    expect { OpenSSL::PKey::EC.new }.to raise_error(R509::R509Error)
    OpenSSL::PKey.send(:remove_const, :EC) # remove stubbed EC
    OpenSSL::PKey::EC = ec # add the real one back
    # this pretty fragile. if the expectation fails then we don't fix the EC class assignment
    # so any spec called after this will fail improperly.
  end
end
