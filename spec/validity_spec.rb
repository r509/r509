require 'spec_helper'
require 'r509/Validity'
require 'openssl'

describe R509::Validity do
    context "status" do
        it "has no status" do
            status = R509::Validity::Status.new
            status.status.should == nil
            status.ocsp_status.should == OpenSSL::OCSP::V_CERTSTATUS_UNKNOWN
        end
        it "has a valid status" do
            status = R509::Validity::Status.new(:status => R509::Validity::VALID)
            status.status.should == R509::Validity::VALID
            status.ocsp_status.should == OpenSSL::OCSP::V_CERTSTATUS_GOOD
        end
        it "has a revoked status" do
            status = R509::Validity::Status.new(:status => R509::Validity::REVOKED)
            status.status.should == R509::Validity::REVOKED
            status.ocsp_status.should == OpenSSL::OCSP::V_CERTSTATUS_REVOKED
        end
        it "has an unknown status" do
            status = R509::Validity::Status.new(:status => R509::Validity::UNKNOWN)
            status.status.should == R509::Validity::UNKNOWN
            status.ocsp_status.should == OpenSSL::OCSP::V_CERTSTATUS_UNKNOWN
        end
        it "has some other status that we don't know about" do
            status = R509::Validity::Status.new(:status => 10101010101)
            status.status.should == 10101010101
            status.ocsp_status.should == OpenSSL::OCSP::V_CERTSTATUS_UNKNOWN
        end
        it "has no revocation time or reason specified" do
            status = R509::Validity::Status.new
            status.revocation_time.should == nil
            status.revocation_reason.should == 0
        end
        it "specifies a revocation time" do
            time = Time.now.to_i
            status = R509::Validity::Status.new(:revocation_time => time)
            status.revocation_time.should == time
        end
        it "specifies a revocation reason" do
            status = R509::Validity::Status.new(:revocation_reason => 2)
            status.revocation_reason.should == 2
        end
    end
    context "writer base" do
        it "calls issue" do
            writer = R509::Validity::Writer.new
            expect { writer.issue(1) }.to raise_error(NotImplementedError, "You must call #issue on a subclass of Writer")
        end
        it "calls revoke" do
            writer = R509::Validity::Writer.new
            expect { writer.revoke(1, 1) }.to raise_error(NotImplementedError, "You must call #revoke on a subclass of Writer")
        end
    end
    context "checker base" do
        it "calls check" do
            checker = R509::Validity::Checker.new
            expect { checker.check(1) }.to raise_error(NotImplementedError, "You must call #check on a subclass of Checker")
        end
    end
    context "writer default" do
        it "calls issue" do
            writer = R509::Validity::DefaultWriter.new
            writer.issue(1)
        end
        it "calls revoke" do
            writer = R509::Validity::DefaultWriter.new
            writer.revoke(1, 1)
        end
    end
    context "checker default" do
        it "calls check" do
            checker = R509::Validity::DefaultChecker.new
            status = checker.check(1)
            status.status.should == R509::Validity::VALID
        end
    end
end
