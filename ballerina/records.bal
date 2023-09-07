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
# + x509Token - The path or token of the X509 certificate
public type UTRecord record {|
    xml envelope;
    string username;
    string password;
    PasswordType passwordType;
    X509Token|string? x509Token = ();
|};

# Represents the record for Timestamp Token.
#
# + envelope - The SOAP envelope  
# + timeToLive - The time to get expired
public type TSRecord record {|
    xml envelope;
    int timeToLive = 300;
|};

# Represents the record for X509 Token.
#
# + envelope - The SOAP envelope  
# + username - The name of the user  
# + password - The password of the user  
# + passwordType - The password type of the username token
# + x509Token - The path or token of the X509 certificate
public type X509Record record {|
    xml envelope;
    string username;
    string password;
    PasswordType passwordType;
    X509Token|string x509Token;
|};

# Represents the record for Username Token with Encryption.
#
# + envelope - The SOAP envelope  
# + username - The name of the user  
# + password - The password of the user  
# + passwordType - The password type of the username token 
# + encryptionKey - The key to encrypt the SOAP body
# + encryptionAlgorithm - The algorithm to encrypt the SOAP body
# + x509Token - The path or token of the X509 certificate
public type UTEncryption record {|
    xml envelope;
    string username;
    string password;
    PasswordType passwordType;
    crypto:PublicKey|crypto:PrivateKey? encryptionKey = ();
    EncryptionAlgorithm encryptionAlgorithm;
    X509Token|string? x509Token = ();
|};

# Represents the record for Username Token with Signature.
#
# + envelope - The SOAP envelope
# + username - The name of the user
# + password - The password of the user
# + passwordType - The password type of the username token
# + signatureKey - The key to sign the SOAP envelope
# + signatureAlgorithm - The algorithm to sign the SOAP envelope
# + x509Token - The path or token of the X509 certificate
public type UTSignature record {|
    xml envelope;
    string username;
    string password;
    PasswordType passwordType;
    crypto:PrivateKey signatureKey;
    SignatureAlgorithm signatureAlgorithm;
    X509Token|string? x509Token = ();
|};

# Represents the record for Username Token with Signature and Encryption.
#
# + envelope - The SOAP envelope
# + username - The name of the user
# + password - The password of the user
# + passwordType - The password type of the username token
# + signatureKey - The key to sign the SOAP envelope 
# + encryptionKey - The key to encrypt the SOAP envelope  
# + signatureAlgorithm - The algorithm to sign the SOAP envelope
# + encryptionAlgorithm - The algorithm to encrypt the SOAP body  
# + x509Token - The path or token of the X509 certificate
public type UTSignAndEncrypt record {|
    xml envelope;
    string username;
    string password;
    PasswordType passwordType;
    crypto:PrivateKey signatureKey;
    crypto:PublicKey|crypto:PrivateKey encryptionKey;
    SignatureAlgorithm signatureAlgorithm;
    EncryptionAlgorithm encryptionAlgorithm;
    X509Token|string? x509Token = ();
|};

# Represents the record for Username Token with Symmetric Binding.
#
# + envelope - The SOAP envelope
# + username - The name of the user
# + password - The password of the user
# + passwordType - The password type of the username token  
# + symmetricKey - The key to sign and encrypt the SOAP envelope  
# + signatureAlgorithm - The algorithm to sign the SOAP envelope
# + encryptionAlgorithm - The algorithm to encrypt the SOAP body 
# + x509Token - The path or token of the X509 certificate
public type UTSymmetricBinding record {|
    xml envelope;
    string username;
    string password;
    PasswordType passwordType;
    crypto:PrivateKey symmetricKey;
    SignatureAlgorithm signatureAlgorithm;
    EncryptionAlgorithm encryptionAlgorithm;
    X509Token|string? x509Token = ();
|};

# Represents the record for Username Token with Symmetric Binding.
#
# + envelope - The SOAP envelope
# + username - The name of the user
# + password - The password of the user
# + passwordType - The password type of the username token   
# + senderPrivateKey - The private key of the client to sign the SOAP envelope  
# + receiverPublicKey - The public key of the server to encrypt the SOAP body
# + signatureAlgorithm - The algorithm to sign the SOAP envelope
# + encryptionAlgorithm - The algorithm to encrypt the SOAP body 
# + x509Token - The path or token of the X509 certificate
public type UTAsymmetricBinding record {|
    xml envelope;
    string username;
    string password;
    PasswordType passwordType;
    crypto:PrivateKey senderPrivateKey;
    crypto:PublicKey receiverPublicKey;
    SignatureAlgorithm signatureAlgorithm;
    EncryptionAlgorithm encryptionAlgorithm;
    X509Token|string? x509Token = ();
|};
