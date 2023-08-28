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
public enum types {
    SYMMETRIC_SIGN_AND_ENCRYPT = "SYMMETRIC_SIGN_AND_ENCRYPT",
    ASYMMETRIC_SIGN_AND_ENCRYPT = "ASYMMETRIC_SIGN_AND_ENCRYPT"
}

public enum AuthType {
    NONE,
    SIGN,
    ENCRYPT,
    SIGN_AND_ENCRYPT
}

public enum PasswordTypes {
    TEXT = "TEXT",
    DIGEST = "DIGEST"
}

public enum BindingType {
    TRANSPORT = "TransportBinding",
    SYMMETRIC = "SymmetricBinding",
    ASYMMETRIC = "AsymmetricBinding"
}

public enum SignatureAlgorithms {
    RSA = "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    HMAC_SHA1 = "http://www.w3.org/2000/09/xmldsig#hmac-sha1",
    HMAC_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
    HMAC_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384",
    HMAC_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512"
}

public enum EncryptionTypes {
    AES_128 = "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
    AES_256 = "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
    AES_192 = "http://www.w3.org/2001/04/xmlenc#aes192-cbc",
    AES_128_GCM = "http://www.w3.org/2009/xmlenc11#aes128-gcm",
    AES_192_GCM = "http://www.w3.org/2009/xmlenc11#aes192-gcm",
    AES_256_GCM = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
}
