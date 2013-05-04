require 'spec_helper'
require 'r509/engine'

# boilerplate to reset the singleton between tests
class R509::Engine
  def reset
    @engines = {}
  end
end

describe R509::Engine do
  before :each do
    R509::Engine.instance.reset
  end

  it "is a singleton" do
    expect { R509::Engine.new }.to raise_error(StandardError)
  end

  it "raises an error if you don't supply an SO_PATH and ID" do
    expect { R509::Engine.instance.load("not even a hash") }.to raise_error(ArgumentError, "You must supply a hash with both SO_PATH and ID")
    expect { R509::Engine.instance.load({"SO_PATH" => "path"}) }.to raise_error(ArgumentError, "You must supply a hash with both SO_PATH and ID")
  end

  it "load returns a new engine" do
    OpenSSL::Engine.should_receive(:load)
    OpenSSL::Engine.should_receive(:by_id).and_return("mocked_engine")
    engine = R509::Engine.instance.load("SO_PATH" => "/some/path", "ID" => "mocked")
    engine.should == 'mocked_engine'
  end

  it "load returns pre-existing engine" do
    OpenSSL::Engine.should_receive(:load)
    OpenSSL::Engine.should_receive(:by_id).and_return("mocked_engine")
    R509::Engine.instance.load("SO_PATH" => "/some/path", "ID" => "mocked")
    engine = R509::Engine.instance.load("SO_PATH" => "/some/path", "ID" => "mocked")
    engine.should == 'mocked_engine'
  end

  it "returns an engine with []" do
    OpenSSL::Engine.should_receive(:load)
    OpenSSL::Engine.should_receive(:by_id).and_return("mocked_engine")
    R509::Engine.instance.load("SO_PATH" => "/some/path", "ID" => "mocked")
    R509::Engine.instance["mocked"].should == "mocked_engine"
    R509::Engine.instance["other"].should be_nil
  end
end
