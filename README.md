    Copyright 2011 Paul Kehrer

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.


#r509 [![Build Status](https://secure.travis-ci.org/reaperhulk/r509.png)](http://travis-ci.org/reaperhulk/r509)
r509 is a wrapper for various OpenSSL functions to allow easy creation of CSRs, signing of certificates, and revocation via CRL.

##Requirements/Installation

r509 requires the Ruby OpenSSL bindings as well as yaml support (present by default in modern Ruby builds).
To install the gem: ```gem install r509-(version).gem```

##Basic Usage

Inside the gem there is a script directory that contains r509\_csr.rb. You can use this in interactive mode to generate a CSR. More complex usage is found in the unit tests.

##Running Tests
If you want to run the tests for r509 you'll need rspec. Additionally, you may want to install rcov (ruby 1.8 only) and yard for running the code coverage and documentation tasks in the Rakefile. ```rake -T``` for a complete list of rake tasks available.

##Continuous Integration
We run continuous integration tests (using Travis-CI) against 1.8.7, 1.9.2, 1.9.3, and ruby-head.

##Thanks to...
* [Sean Schulte](https://github.com/sirsean)
* [Mike Ryan](https://github.com/justfalter)
