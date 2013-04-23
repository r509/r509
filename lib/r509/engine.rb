require 'singleton'
require 'openssl'

module R509
  class Engine
    include Singleton

    def initialize
      @engines = {}
    end

    def load(hash)
      if not hash.has_key?("SO_PATH") or not hash.has_key?("ID")
        raise ArgumentError, "You must supply a hash with both SO_PATH and ID"
      end
      if @engines.has_key?(hash["ID"])
        @engines[hash["ID"]]
      else
        OpenSSL::Engine.load
        @engines[hash["ID"]] = OpenSSL::Engine.by_id("dynamic") do |e|
          e.ctrl_cmd("SO_PATH",hash["SO_PATH"])
          e.ctrl_cmd("ID",hash["ID"])
          e.ctrl_cmd("LOAD")
        end
      end
    end

    def [](key)
      @engines[key]
    end
  end
end
