require 'singleton'
require 'openssl'

module R509
  # a singleton class to store loaded OpenSSL Engines
  class Engine
    include Singleton

    def initialize
      @engines = {}
    end

    # @param hash Takes a hash with SO_PATH and ID
    # @return OpenSSL::Engine object
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

    # Takes an engine ID and returns the engine object
    def [](key)
      @engines[key]
    end
  end
end
