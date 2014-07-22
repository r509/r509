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

  it "raises an error if you don't supply an :so_path and :id" do
    expect { R509::Engine.instance.load("not even a hash") }.to raise_error(ArgumentError, "You must supply a hash with both :so_path and :id")
    expect { R509::Engine.instance.load(:so_path => "path") }.to raise_error(ArgumentError, "You must supply a hash with both :so_path and :id")
  end

  it "load returns a new engine" do
    expect(OpenSSL::Engine).to receive(:load)
    engine_double = double('engine')
    expect(OpenSSL::Engine).to receive(:by_id).and_yield(engine_double).and_return(engine_double)
    expect(engine_double).to receive(:ctrl_cmd).with("SO_PATH", "/some/path")
    expect(engine_double).to receive(:ctrl_cmd).with("ID", "mocked")
    expect(engine_double).to receive(:ctrl_cmd).with("LOAD")
    engine = R509::Engine.instance.load(:so_path => "/some/path", :id => "mocked")
    expect(engine).to eq(engine_double)
  end

  it "load returns pre-existing engine" do
    expect(OpenSSL::Engine).to receive(:load)
    expect(OpenSSL::Engine).to receive(:by_id).and_return("mocked_engine")
    R509::Engine.instance.load(:so_path => "/some/path", :id => "mocked")
    engine = R509::Engine.instance.load(:so_path => "/some/path", :id => "mocked")
    expect(engine).to eq('mocked_engine')
  end

  it "returns an engine with []" do
    expect(OpenSSL::Engine).to receive(:load)
    expect(OpenSSL::Engine).to receive(:by_id).and_return("mocked_engine")
    R509::Engine.instance.load(:so_path => "/some/path", :id => "mocked")
    expect(R509::Engine.instance["mocked"]).to eq("mocked_engine")
    expect(R509::Engine.instance["other"]).to be_nil
  end
end
