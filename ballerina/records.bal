// Copyright (c) 2023, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
//
// WSO2 Inc. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
import ballerina/crypto;

# Represents the record for Username Token policy.
#
# + envelope - The SOAP envelope
# + username - The name of the user
# + password - The password of the user
# + passwordType - The password type of the username token
public type UsernameTokenConfig record {|
    xml envelope;
    string username;
    string password;
    PasswordType passwordType;
|};

# Represents the record for Timestamp Token policy.
#
# + envelope - The SOAP envelope
# + timeToLive - The time to get expired
public type TimestampTokenConfig record {|
    xml envelope;
    int timeToLive = 300;
|};

# Represents the record for Symmetric Binding policy.
#
# + envelope - The SOAP envelope
# + symmetricKey - The key to sign and encrypt the SOAP envelope
# + signatureAlgorithm - The algorithm to sign the SOAP envelope
# + encryptionAlgorithm - The algorithm to encrypt the SOAP envelope
# + x509Token - The path or token of the X509 certificate
public type SymmetricBindingConfig record {|
    xml envelope;
    crypto:PrivateKey symmetricKey;
    SignatureAlgorithm signatureAlgorithm?;
    EncryptionAlgorithm encryptionAlgorithm?;
    string x509Token?;
|};

# Represents the record for Username Token with Asymmetric Binding policy.
#
# + envelope - The SOAP envelope
# + senderPrivateKey - The private key of the client to sign the SOAP envelope
# + receiverPublicKey - The public key of the server to encrypt the SOAP body
# + signatureAlgorithm - The algorithm to sign the SOAP envelope
# + encryptionAlgorithm - The algorithm to encrypt the SOAP body
# + x509Token - The path or token of the X509 certificate
public type AsymmetricBindingConfig record {|
    xml envelope;
    crypto:PrivateKey senderPrivateKey;
    crypto:PublicKey receiverPublicKey;
    SignatureAlgorithm signatureAlgorithm?;
    EncryptionAlgorithm encryptionAlgorithm?;
    string x509Token?;
|};

# Union type of all the web service security configurations.
public type WsSecurityConfig UsernameTokenConfig|TimestampTokenConfig|SymmetricBindingConfig|AsymmetricBindingConfig;
