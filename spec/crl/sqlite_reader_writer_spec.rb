require 'spec_helper'
require 'r509/crl/sqlite_reader_writer'
module R509
  module CRL
    describe SqliteReaderWriter do
  
      let(:empty_db) { SQLite3::Database.new ':memory:' }
      let(:db) {
        db = SQLite3::Database.new ':memory:'
        db.execute_batch SqliteReaderWriter::DB_SCHEMA
        db.execute "INSERT INTO revoked_serials (serial, reason, revoked_at) VALUES ('12345',0,1323983885), ('12346',null,1323983885)"
        db
      }
      let(:rw) { SqliteReaderWriter.new db } 

      it 'creates the schema automaticaly if its missing' do
        SqliteReaderWriter.new empty_db 
        db.execute('SELECT * FROM sqlite_master').should_not be_empty
      end

      it 'reads a crl list' do
        admin = double("admin")
        admin.should_receive(:revoke_cert).with(12345, 0, 1323983885, false)
        admin.should_receive(:revoke_cert).with(12346, nil, 1323983885, false)
        rw.read_list(admin)
      end

      it 'writes a crl list entry' do
        rw.write_list_entry(1,1,nil)
        db.execute("SELECT * FROM revoked_serials WHERE serial='1' AND revoked_at=1 AND reason is null").should_not be_empty
      end

      it 'removes a crl list entry' do
        rw.remove_list_entry(12345)
        db.execute("SELECT * FROM revoked_serials WHERE serial='12345'").should be_empty
      end

      it 'reads a number' do
        db.execute("UPDATE crl_number set number=5")
        rw.read_number.should == 5
      end

      it 'writes a crl number' do
        rw.write_number 6
        db.get_first_value("SELECT number from crl_number").should == 6
      end
    end

  end
end
