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
      if not hash.respond_to?(:has_key?) or not hash.has_key?(:so_path) or not hash.has_key?(:id)
        raise ArgumentError, "You must supply a hash with both :so_path and :id"
      end
      if @engines.has_key?(hash[:id])
        @engines[hash[:id]]
      else
        OpenSSL::Engine.load
        @engines[hash[:id]] = OpenSSL::Engine.by_id("dynamic") do |e|
          e.ctrl_cmd("SO_PATH",hash[:so_path])
          e.ctrl_cmd("ID",hash[:id])
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
