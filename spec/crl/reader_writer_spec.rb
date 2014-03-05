require 'spec_helper'
require 'stringio'

describe R509::CRL::ReaderWriter do
  before :all do
    @rw = R509::CRL::ReaderWriter.new
  end

  it "abstract base class raises error for write_list_entry" do
    expect { @rw.write_list_entry }.to raise_error(NotImplementedError)
  end

  it "abstract base class raises error for remove_list_entry" do
    expect { @rw.remove_list_entry }.to raise_error(NotImplementedError)
  end

  it "abstract base class raises error for write_number" do
    expect { @rw.write_number }.to raise_error(NotImplementedError)
  end

  it "abstract base class raises error for read_list" do
    expect { @rw.read_list }.to raise_error(NotImplementedError)
  end

  it "abstract base class raises error for read_number" do
    expect { @rw.read_number }.to raise_error(NotImplementedError)
  end
end

describe R509::CRL::FileReaderWriter do
  before :each do
    @rw = R509::CRL::FileReaderWriter.new
  end

  it "handles nil crl_list_file in read_list" do
    @rw.crl_list_file = nil
    @rw.read_list.should == nil
  end

  it "handles nil crl_list_file in write_list_entry" do
    @rw.crl_list_file = nil
    @rw.write_list_entry(1,1,nil).should == nil
  end

  it "handles nil crl_number_file in read_number" do
    @rw.crl_number_file = nil
    @rw.read_number.should == 0
  end

  it "handles nil crl_number_file in write_number" do
    @rw.crl_number_file = nil
    @rw.write_number(0).should == nil
  end

  it "reads a crl list" do
    @rw.crl_list_file = TestFixtures::CRL_LIST_FILE
    expect { |b| @rw.read_list(&b) }.to yield_successive_args(
        [12345, 0, 1323983885], 
        [ 12346, nil, 1323983885]
    )
   
  end

  it "writes a crl list entry" do
    sio = StringIO.new
    @rw.crl_list_file = sio
    @rw.write_list_entry(1,1,nil)
    sio.string.should == "1,1,\n"
    @rw.write_list_entry(2,2,1)
    sio.string.should == "1,1,\n2,2,1\n"
  end

  it "removes a crl list entry" do
    sio = StringIO.new
    @rw.crl_list_file = sio
    @rw.write_list_entry(1,1,nil)
    sio.string.should == "1,1,\n"
    @rw.write_list_entry(2,2,1)
    sio.string.should == "1,1,\n2,2,1\n"
    @rw.remove_list_entry(2)
    sio.string.should == "1,1,\n"
  end

  it "reads a number" do
    sio = StringIO.new
    sio.write("500")
    sio.rewind # rewind the pointer to the beginning so the next read catche the 500
    @rw.crl_number_file = sio
    @rw.read_number.should == 500
  end

  it "writes a crl number" do
    sio = StringIO.new
    @rw.crl_number_file = sio
    @rw.write_number(30)
    @rw.crl_number_file.string.should == "30"
  end
end
