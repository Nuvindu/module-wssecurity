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

# Represents the record for Username Token.
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

# Represents the record for Timestamp Token.
#
# + envelope - The SOAP envelope  
# + timeToLive - The time to get expired
public type TimestampTokenConfig record {|
    xml envelope;
    int timeToLive = 300;
|};

# Represents the record for Username Token with Signature.
#
# + signatureKey - The key to sign the SOAP envelope
# + signatureAlgorithm - The algorithm to sign the SOAP envelope
public type UtSignatureConfig record {|
    *UsernameTokenConfig;
    crypto:PrivateKey signatureKey;
    SignatureAlgorithm signatureAlgorithm;
|};

# Represents the record for X509 Token with Signature.
#
# + signatureKey - The key to sign the SOAP envelope
# + signatureAlgorithm - The algorithm to sign the SOAP envelope
# + x509Token - The path or token of the X509 certificate
public type X509SignatureConfig record {|
    *UsernameTokenConfig;
    crypto:PrivateKey signatureKey;
    SignatureAlgorithm signatureAlgorithm;
    X509Token|string x509Token;
|};

# Represents the record for Username Token with Encryption.
#
# + encryptionKey - The key to encrypt the SOAP body
# + encryptionAlgorithm - The algorithm to encrypt the SOAP body
public type UtEncryptionConfig record {|
    *UsernameTokenConfig;
    crypto:PublicKey|crypto:PrivateKey? encryptionKey = ();
    EncryptionAlgorithm encryptionAlgorithm;
|};

# Represents the record for Username Token with Symmetric Binding.
#
# + symmetricKey - The key to sign and encrypt the SOAP envelope
# + signatureAlgorithm - The algorithm to sign the SOAP envelope
# + encryptionAlgorithm - The algorithm to encrypt the SOAP body
public type UtSymmetricBindingConfig record {|
    *UsernameTokenConfig;
    crypto:PrivateKey symmetricKey;
    SignatureAlgorithm signatureAlgorithm;
    EncryptionAlgorithm encryptionAlgorithm;
|};

# Represents the record for Username Token with Symmetric Binding.
# 
# + senderPrivateKey - The private key of the client to sign the SOAP envelope
# + receiverPublicKey - The public key of the server to encrypt the SOAP body
# + signatureAlgorithm - The algorithm to sign the SOAP envelope
# + encryptionAlgorithm - The algorithm to encrypt the SOAP body
public type UtAsymmetricBindingConfig record {|
    *UsernameTokenConfig;
    crypto:PrivateKey senderPrivateKey;
    crypto:PublicKey receiverPublicKey;
    SignatureAlgorithm signatureAlgorithm;
    EncryptionAlgorithm encryptionAlgorithm;
|};

# Represents the record for X509 Token with Symmetric Binding.
#
# + symmetricKey - The key to sign and encrypt the SOAP envelope
# + signatureAlgorithm - The algorithm to sign the SOAP envelope
# + encryptionAlgorithm - The algorithm to encrypt the SOAP body
# + x509Token - The path or token of the X509 certificate
public type X509SymmetricBindingConfig record {|
    *UsernameTokenConfig;
    crypto:PrivateKey symmetricKey;
    SignatureAlgorithm signatureAlgorithm;
    EncryptionAlgorithm encryptionAlgorithm;
    X509Token|string x509Token;
|};

# Represents the record for X509 Token with Asymmetric Binding.
#
# + senderPrivateKey - The private key of the client to sign the SOAP envelope
# + receiverPublicKey - The public key of the server to encrypt the SOAP body
# + signatureAlgorithm - The algorithm to sign the SOAP envelope
# + encryptionAlgorithm - The algorithm to encrypt the SOAP body
# + x509Token - The path or token of the X509 certificate
public type X509AsymmetricBindingConfig record {|
    *UsernameTokenConfig;
    crypto:PrivateKey senderPrivateKey;
    crypto:PublicKey receiverPublicKey;
    SignatureAlgorithm signatureAlgorithm;
    EncryptionAlgorithm encryptionAlgorithm;
    X509Token|string x509Token;
|};
