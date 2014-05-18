require 'sqlite3'
module R509
  module CRL
    # SQLite-based reader/writer for CRL data.
    class SQLiteReaderWriter < R509::CRL::ReaderWriter
      # Create an SQLite based persistence
      # @param filename_or_db filepath to an SQLite database or an SQLite3::Database object
      def initialize(filename_or_db)
        if filename_or_db.kind_of? SQLite3::Database
          @db = filename_or_db
        else
          @db = SQLite3::Database.new(file)
        end
        # create tables if missing
        ensure_schema
      end

      # Reads a CRL list file from the SQLite database
      # @yield For each revoked certificate in the CRL
      # @yieldparam serial [Integer] revoked certificate's serial number
      # @yieldparam reason [Integer,nil] reason for revocation.
      # @yieldparam revoke_time [Integer]
      def read_list
        @db.execute('SELECT serial,reason,revoked_at from revoked_serials') do |row|
          serial = row[0].to_i
          reason = row[1]
          revoke_time = row[2]
          yield serial, reason, revoke_time
        end
        nil
      end

      # Appends a CRL list entry to the SQLite database
      # @param serial [Integer] serial number of the certificate to revoke
      # @param reason [Integer,nil] reason for revocation
      # @param revoke_time [Integer]
      def write_list_entry(serial, revoke_time, reason)
        @db.execute('INSERT INTO revoked_serials (serial, revoked_at, reason) VALUES (?,?,?)', serial.to_s, revoke_time, reason)
      end

      # Remove a CRL list entry from SQLite
      # @param serial [Integer] serial number of the certificate to remove from the list
      def remove_list_entry(serial)
        @db.execute('DELETE FROM revoked_serials WHERE serial=?', serial.to_s)
      end

      # read the CRL number from SQLite
      def read_number
        @db.get_first_value 'SELECT number from crl_number'
      end

      # write the CRL number to SQLite
      def write_number(crl_number)
        @db.execute('UPDATE crl_number SET number=?', crl_number)
      end

      private

      def ensure_schema
        if @db.execute('SELECT * FROM sqlite_master WHERE type=? AND name=?', 'table', 'revoked_serials').empty?
          @db.execute_batch <<-EOSCHEMA
            CREATE TABLE revoked_serials(
               serial TEXT NOT NULL PRIMARY KEY,
               reason INTEGER,
               revoked_at INTEGER NOT NULL
            );
            CREATE TABLE crl_number(
              number INTEGER NOT NULL DEFAULT 0
            );
            INSERT INTO crl_number DEFAULT VALUES;
          EOSCHEMA
        end
      end
    end
  end
end
