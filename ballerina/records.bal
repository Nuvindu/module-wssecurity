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

public type UTRecord record {|
    string username;
    string password;
    string passwordType;
    X509Token|string? x509Token = ();
|};

public type TSRecord record {|
    int timeToLive = 300;
|};

public type X509Record record {|
    string username;
    string password;
    string passwordType;
    X509Token|string x509Token;
|};

public type UTEncryption record {|
    string username;
    string password;
    string passwordType;
    crypto:PublicKey|crypto:PrivateKey? encryptionKey = ();
    EncryptionAlgorithm encryptionAlgorithm;
    X509Token|string? x509Token = ();
|};

public type UTSignature record {|
    string username;
    string password;
    string passwordType;
    crypto:PrivateKey signatureKey;
    SignatureAlgorithm signatureAlgorithm;
    X509Token|string? x509Token = ();
|};

public type UTSymmetricBinding record {|
    string username;
    string password;
    string passwordType;
    crypto:PrivateKey symmetricKey;
    SignatureAlgorithm signatureAlgorithm;
    EncryptionAlgorithm encryptionAlgorithm;
    X509Token|string? x509Token = ();
|};

public type UTAsymmetricBinding record {|
    string username;
    string password;
    string passwordType;
    crypto:PrivateKey senderPrivateKey;
    crypto:PublicKey receiverPublicKey;
    SignatureAlgorithm signatureAlgorithm;
    EncryptionAlgorithm encryptionAlgorithm;
    X509Token|string? x509Token = ();
|};
