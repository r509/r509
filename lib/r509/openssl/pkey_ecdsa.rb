# vim: set sts=2 ts=2 sw=2 et:
if defined?(OpenSSL::PKey::EC) && !defined?(OpenSSL::PKey::EC::UNSUPPORTED)
  module OpenSSL::PKey
    class ECDSA < OpenSSL::PKey::EC
      @initialized = false

      def self.generate(arg)
        if (arg.kind_of? String) || (arg.kind_of? Symbol)
          curve_name = arg.to_s
          if !OpenSSL::PKey::EC.builtin_curves.any?{|c|c[0]  == curve_name}
            raise OpenSSL::PKey::ECError, "unknown curve name (#{curve_name})"
          end
          group = OpenSSL::PKey::EC::Group.new(curve_name)
        elsif arg.kind_of? OpenSSL::PKey::EC::Group
          group = arg
        else
          raise OpenSSL::PKey::ECError, "Must provide group or curve"
        end
        self.new(group)
      end

      # Takes two inputs, ec_param and ec_point, as per PKCS#11
      def self.from_pkcs11(ec_param, ec_point)
        params = OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::ObjectId.new("1.2.840.10045.2.1"), # id-ecPublicKey
          ec_param
        ])
        # OpenSSL wants a BitString for the point, PKCS#11 gives OctetString
        # So decode and rebuild
        pubkey = OpenSSL::ASN1::Sequence.new([
          params,
          OpenSSL::ASN1::BitString.new(OpenSSL::ASN1.decode(ec_point).value)
        ])
        self.new(pubkey.to_der)
      end

      # trick to track whether arg was passed is from
      # http://stackoverflow.com/q/23765914

      # Generates or loads an ECDSA keypair.
      # If arg is a Group, then it generates a new key using that group
      #   The second parameter can be a Point, which will make a public key
      # If arg is a Point, then it becomes a public key
      # If arg is a symbol, then is generates a new key using that as the
      #   group name
      # If arg is a string, then it tries to use that as name of a file
      #   contain PEM or DER enoded data; failing that it is the literal
      #   PEM or DER encoded data

      def initialize(arg, pass = (no_pass = true; nil))
        if arg.kind_of? OpenSSL::PKey::EC::Group
          if !no_pass
            if !pass.kind_of OpenSSL::PKey::EC::Point
              raise OpenSSL::PKey::ECError, "only a Point is allowed when supplying group"
            elsif !pass.group.eql? arg
              raise OpenSSL::PKey::ECError, "Point group does not match requested group"
            end
          end
          super(arg)
          if no_pass
            self.generate_key
          else
            self.pub_key = pass
          end
        elsif arg.kind_of? OpenSSL::PKey::EC::Point
          # Points have a group, so we have all we need
          super(arg.group)
          self.pub_key = arg
        elsif arg.is_a? OpenSSL::PKey::EC
          # "Cast" to ECDSA
          if !no_pass
            raise OpenSSL::PKey::ECError, "password not allowed when supplying key"
          end
          if !(arg.public_key? || arg.private_key?)
            raise OpenSSL::PKey::ECError, "key has not been generated"
          end
          super(arg.group)
          if arg.public_key?
            self.pub_key = arg.public_key
          end
          if arg.private_key?
            self.priv_key = arg.private_key
          end
        elsif arg.kind_of? String
          if no_pass
            super(arg)
          else
            super(arg, pass)
          end
          if !(self.public? || self.private?)
            raise OpenSSL::PKey::ECError, "Neither PUB key nor PRIV key found"
          end
          k.check_key
        elsif arg.kind_of? Symbol
          if !no_pass
            raise OpenSSL::PKey::ECError, "password not allowed when supplying curve name"
          end
          curve_name = arg.to_s
          if !OpenSSL::PKey::EC.builtin_curves.any?{|c|c[0]  == curve_name}
            raise OpenSSL::PKey::ECError, "unknown curve name (#{curve_name})"
          end
          
          # Explicitly create the group to ensure EC.new makes the right
          # decision on what we are doing (EC::Group.new could still get
          # confused)
          group = OpenSSL::PKey::EC::Group.new(curve_name)
          super(group)
          self.generate_key
        else
          raise OpenSSL::PKey::ECError, "Neither PUB key nor PRIV key"
        end
        @initialized = true
      end

      def generate_key
        super
        self.check_key
      end

      def group=(*args)
        if @initialized
          raise OpenSSL::PKey::ECError, "Changing group is not permitted"
        end
        super(*args)
      end

      def private?
        self.private_key?
      end

      def public?
        self.public_key?
      end

      # Allow the "raw" public key to be accessed via pub_key
      alias_method :pub_key, :public_key

      alias_method :priv_key, :private_key

      # A point
      def pub_key=(arg)
        if !arg.kind_of? OpenSSL::PKey::EC::Point
          raise OpenSSL::PKey::ECError, "public key must be a Point"
        end
        if !self.group.eql? arg.group
          raise OpenSSL::PKey::ECError, "Point group does not match existing group"
        end
        if arg.infinity?
          raise OpenSSL::PKey::ECError, "Refusing to use point-at-infinity"
        end
        if !arg.on_curve?
          raise OpenSSL::PKey::ECError, "Refusing to use a point not on the curve"
        end
        self.public_key = arg
        self.check_key
        self.pub_key
      end

      def priv_key=(arg)
        if !arg.kind_of? OpenSSL::BN
          raise OpenSSL::PKey::ECError, "private key must be a BN"
        end
        self.private_key = arg
        self.check_key
        self.priv_key
      end

      def public_key
        OpenSSL::PKey::ECDSA.new(self.pub_key)
      end

      def params
        hash = {}
        hash["group"] = self.group
        hash["pub_key"] = self.pub_key
        hash["priv_key"] = self.priv_key
        hash
      end
    end
  end
end
