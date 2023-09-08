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
import ballerina/regex;

function addSecurityHeader(Document document) returns WSSecurityHeader|Error {
    WSSecurityHeader wsSecHeader = check new (document);
    Error? insertHeader = wsSecHeader.insertSecHeader();
    if insertHeader is () {
        return wsSecHeader;
    }
    return insertHeader;
}

function getEnvelopeBody(xml envelope) returns string|Error {
    Document document = check new (envelope);
    return document.getEnvelopeBody();
}

function addTimestampToken(WSSecurityHeader wsSecHeader, int timeToLive) returns TimestampToken|Error {
    if timeToLive <= 0 {
        return error Error("Invalid value for `timeToLive`");
    }
    TimestampToken timestampToken = new (wsSecHeader, timeToLive);
    return timestampToken;
}

function decryptData(byte[] cipherText, EncryptionAlgorithm encryptionAlgorithm,
                            crypto:PrivateKey|crypto:PublicKey? key = ()) returns byte[]|Error {
    Encryption encrypt = check new();                            
    return encrypt.decryptData(cipherText, encryptionAlgorithm, key);
}

function addSignature(Signature sign, string signatureAlgorithm, byte[] signature) returns Signature|Error {
    sign.setSignatureAlgorithm(signatureAlgorithm);
    sign.setSignatureValue(signature);
    return sign;
}

function addEncryption(Encryption encrypt , string encryptionAlgorithm, byte[] encryption) returns Encryption|Error {
    encrypt.setEncryptionAlgorithm(encryptionAlgorithm);
    encrypt.setEncryptedData(encryption);
    return encrypt;
}

function addUsernameToken(WSSecurityHeader wsSecHeader, string username, string password,
                                    PasswordType passwordType, AuthType authType = NONE) returns UsernameToken {
    UsernameToken usernameToken = new(wsSecHeader, username, password, passwordType);
    usernameToken.setAuthType(authType);
    return usernameToken;
}

function addX509Token(string|X509Token x509certToken, UsernameToken ut) returns UsernameToken|Error {
    X509Token x509Token;
    if x509certToken is string {
        x509Token = check new (x509certToken);
    } else {
        x509Token = x509certToken;
    }
    x509Token.addX509Token(ut);
    return ut;
}

function generateEnvelope(Token token, Encryption encryption = check new, 
                          Signature signature = check new) returns xml|Error {
    if token is TimestampToken {
        string envelope = check token.addTimestamp();
        do {
            return check xml:fromString(regex:replace(envelope, string`<?.*?><`, "<"));
        } on fail var e {
        	return error Error(e.message());
        }
    }
    if token is UsernameToken {
        string envelope = check token.populateHeaderData(token.getUsername(), token.getPassword(), token.getPasswordType(),
                                                         encryption, signature, token.getAuthType());
        do {
            return check xml:fromString(regex:replace(envelope, string`<?.*?><`, "<"));
        } on fail var e {
        	return error Error(e.message());
        }
    }
    return error("WS Security policy headers are not set.");
}

# Returns the encrypted data of the SOAP envelope.
#
# + envelope - The SOAP envelope
# + return - A `byte[]` if the encrypted data is successfully decoded or else `wssec:Error`
public function getEncryptedData(xml envelope) returns byte[]|Error {
    Document document = check new (envelope);
    return document.getEncryptedData();
}

# Returns the signed data of the SOAP envelope.
#
# + envelope - The SOAP envelope
# + return - A `byte[]` if the signed data is successfully decoded or else `wssec:Error`
public function getSignatureData(xml envelope) returns byte[]|Error {
    Document document = check new (envelope);
    return document.getSignatureData();
}

# Apply timestamp token security policy to the SOAP envelope.
# 
# + tsRecord - The `TSRecord` record with the required parameters
# + return - A `xml` type of SOAP envelope if the security binding is successfully added or else `wssec:Error`
public function applyTimestampToken(*TimestampTokenConfig tsRecord) returns xml|Error {
    Document document = check new(tsRecord.envelope);
    WSSecurityHeader wSSecurityHeader = check addSecurityHeader(document);
    TimestampToken timestampToken = check addTimestampToken(wSSecurityHeader, tsRecord.timeToLive);
    return check generateEnvelope(timestampToken);
}

# Apply username token security policy to the SOAP envelope.
# 
# + utRecord - The `UsernameTokenConfig` record with the required parameters
# + return - A `xml` type of SOAP envelope if the security binding is successfully added or else `wssec:Error`
public function applyUsernameToken(*UsernameTokenConfig utRecord) returns xml|Error {
    Document document = check new(utRecord.envelope);
    WSSecurityHeader wSSecurityHeader = check addSecurityHeader(document);
    UsernameToken usernameToken = addUsernameToken(wSSecurityHeader, utRecord.username,
                                                   utRecord.password, utRecord.passwordType, NONE);
    return generateEnvelope(usernameToken);
}

# Apply X509 token security policy with username token to the SOAP envelope.
# 
# + x509Record - The `X509Record` record with the required parameters
# + return - A `xml` type of SOAP envelope if the security binding is successfully added or else `wssec:Error`
public function applyX509Token(*X509TokenConfig x509Record) returns xml|Error {
    Document document = check new(x509Record.envelope);
    WSSecurityHeader wSSecurityHeader = check addSecurityHeader(document);
    UsernameToken usernameToken = addUsernameToken(wSSecurityHeader, x509Record.username, x509Record.password,
                                                   x509Record.passwordType, NONE);
    UsernameToken usernameTokenWithX509 = check addX509Token(x509Record.x509Token, usernameToken);
    return generateEnvelope(usernameTokenWithX509);
}

# Apply username token security policy with signature to the SOAP envelope.
# 
# + utSignature - The `UtSignatureConfig` record with the required parameters
# + return - A `xml` type of SOAP envelope if the security binding is successfully added or else `wssec:Error`
public function applyUTSignature(*UtSignatureConfig utSignature) returns xml|Error {
    Document document = check new(utSignature.envelope);
    WSSecurityHeader wSSecurityHeader = check addSecurityHeader(document);
    Signature signature = check new();
    byte[] signedData = check signature.signData(check getEnvelopeBody(utSignature.envelope), 
                                                 utSignature.signatureAlgorithm, utSignature.signatureKey);
    Signature signatureResult = check addSignature(signature, utSignature.signatureAlgorithm, signedData);
    UsernameToken usernameToken = addUsernameToken(wSSecurityHeader, utSignature.username, utSignature.password,
                                                   utSignature.passwordType, SIGNATURE);
    return check generateEnvelope(usernameToken, signature = signatureResult);
}

# Apply X509 token security policy with signature to the SOAP envelope.
# 
# + x509Signature - The `X509SignatureConfig` record with the required parameters
# + return - A `xml` type of SOAP envelope if the security binding is successfully added or else `wssec:Error`
public function applyX509Signature(*X509SignatureConfig x509Signature) returns xml|Error {
    Document document = check new(x509Signature.envelope);
    WSSecurityHeader wSSecurityHeader = check addSecurityHeader(document);
    Signature signature = check new();
    byte[] signedData = check signature.signData(check getEnvelopeBody(x509Signature.envelope), 
                                                 x509Signature.signatureAlgorithm, x509Signature.signatureKey);
    Signature signatureResult = check addSignature(signature, x509Signature.signatureAlgorithm, signedData);
    UsernameToken usernameToken = addUsernameToken(wSSecurityHeader, x509Signature.username, x509Signature.password,
                                                   x509Signature.passwordType, SIGNATURE);
    X509Token|string? x509Token = x509Signature.x509Token;
    if x509Token !is () {
        usernameToken = check addX509Token(x509Token, usernameToken);
    }
    return check generateEnvelope(usernameToken, signature = signatureResult);
}

# Apply username token security policy with encryption to the SOAP envelope.
# 
# + utEncryption - The `UtEncryptionConfig` record with the required parameters
# + return - A `xml` type of SOAP envelope if the security binding is successfully added or else `wssec:Error`
public function applyUtEncryption(*UtEncryptionConfig utEncryption) returns xml|Error {
    Document document = check new(utEncryption.envelope);
    WSSecurityHeader wSSecurityHeader = check addSecurityHeader(document);
    Encryption encryption = check new();
    byte[] encryptData = check encryption.encryptData(check getEnvelopeBody(utEncryption.envelope),
                                                      utEncryption.encryptionAlgorithm,
                                                      utEncryption.encryptionKey);
    Encryption encryptionResult = check addEncryption(encryption, utEncryption.encryptionAlgorithm, encryptData);
    UsernameToken usernameToken = addUsernameToken(wSSecurityHeader, utEncryption.username, utEncryption.password,
                                                   utEncryption.passwordType, ENCRYPT);
    return generateEnvelope(usernameToken, encryptionResult);
}

# Apply X509 token security policy with encryption to the SOAP envelope.
# 
# + x509Encryption - The `X509EncryptionConfig` record with the required parameters
# + return - A `xml` type of SOAP envelope if the security binding is successfully added or else `wssec:Error`
public function applyX509Encryption(*X509EncryptionConfig x509Encryption) returns xml|Error {
    Document document = check new(x509Encryption.envelope);
    WSSecurityHeader wSSecurityHeader = check addSecurityHeader(document);
    Encryption encryption = check new();
    byte[] encryptData = check encryption.encryptData(check getEnvelopeBody(x509Encryption.envelope),
                                                      x509Encryption.encryptionAlgorithm,
                                                      x509Encryption.encryptionKey);
    Encryption encryptionResult = check addEncryption(encryption, x509Encryption.encryptionAlgorithm, encryptData);
    UsernameToken usernameToken = addUsernameToken(wSSecurityHeader, x509Encryption.username, x509Encryption.password,
                                                   x509Encryption.passwordType, ENCRYPT);
    usernameToken = check addX509Token(x509Encryption.x509Token, usernameToken);
    return generateEnvelope(usernameToken, encryptionResult);
}

# Apply symmetric binding security policy with username token to the SOAP envelope.
# 
# + utSymmetricBinding - The `UtSymmetricBindingConfig` record with the required parameters
# + return - A `xml` type of SOAP envelope if the security binding is successfully added or else `wssec:Error`
public function applySymmetricBinding(*UtSymmetricBindingConfig utSymmetricBinding) returns xml|Error {
    Document document = check new(utSymmetricBinding.envelope);
    WSSecurityHeader wSSecurityHeader = check addSecurityHeader(document);
    Signature signature = check new();
    byte[] signedData = check signature.signData(check getEnvelopeBody(utSymmetricBinding.envelope), 
                                                 utSymmetricBinding.signatureAlgorithm,
                                                 utSymmetricBinding.symmetricKey);
    Signature signatureResult = check addSignature(signature, utSymmetricBinding.signatureAlgorithm, signedData);
    Encryption encryption = check new();
    byte[] encryptData = check encryption.encryptData(check getEnvelopeBody(utSymmetricBinding.envelope),
                                                      utSymmetricBinding.encryptionAlgorithm,
                                                      utSymmetricBinding.symmetricKey);
    Encryption encryptionResult = check addEncryption(encryption, utSymmetricBinding.encryptionAlgorithm, encryptData);
    UsernameToken usernameToken = addUsernameToken(wSSecurityHeader, utSymmetricBinding.username,
                                                   utSymmetricBinding.password,
                                                   utSymmetricBinding.passwordType, SIGN_AND_ENCRYPT);
    return generateEnvelope(usernameToken, encryptionResult, signatureResult);
}

# Apply symmetric binding security policy with X509 token to the SOAP envelope.
# 
# + x509SymmetricBinding - The `X509SymmetricBindingConfig` record with the required parameters
# + return - A `xml` type of SOAP envelope if the security binding is successfully added or else `wssec:Error`
public function applyX509SymmetricBinding(*X509SymmetricBindingConfig x509SymmetricBinding) returns xml|Error {
    Document document = check new(x509SymmetricBinding.envelope);
    WSSecurityHeader wSSecurityHeader = check addSecurityHeader(document);
    Signature signature = check new();
    byte[] signedData = check signature.signData(check getEnvelopeBody(x509SymmetricBinding.envelope), 
                                                 x509SymmetricBinding.signatureAlgorithm,
                                                 x509SymmetricBinding.symmetricKey);
    Signature signatureResult = check addSignature(signature, x509SymmetricBinding.signatureAlgorithm, signedData);
    Encryption encryption = check new();
    byte[] encryptData = check encryption.encryptData(check getEnvelopeBody(x509SymmetricBinding.envelope),
                                                      x509SymmetricBinding.encryptionAlgorithm,
                                                      x509SymmetricBinding.symmetricKey);
    Encryption encryptionResult = check addEncryption(encryption, x509SymmetricBinding.encryptionAlgorithm,
                                                      encryptData);
    UsernameToken usernameToken = addUsernameToken(wSSecurityHeader, x509SymmetricBinding.username,
                                                   x509SymmetricBinding.password,
                                                   x509SymmetricBinding.passwordType, SIGN_AND_ENCRYPT);
    usernameToken = check addX509Token(x509SymmetricBinding.x509Token, usernameToken);
    return generateEnvelope(usernameToken, encryptionResult, signatureResult);
}

# Apply asymmetric binding security policy with Username token to the SOAP envelope.
# 
# + utAsymmetricBinding - The `UtAsymmetricBindingConfig` record with the required parameters
# + return - A `xml` type of SOAP envelope if the security binding is successfully added or else `wssec:Error`
public function applyUtAsymmetricBinding(*UtAsymmetricBindingConfig utAsymmetricBinding) returns xml|Error {
    Document document = check new(utAsymmetricBinding.envelope);
    WSSecurityHeader wSSecurityHeader = check addSecurityHeader(document);
    Signature signature = check new();
    byte[] signedData = check signature.signData(check getEnvelopeBody(utAsymmetricBinding.envelope), 
                                                 utAsymmetricBinding.signatureAlgorithm,
                                                 utAsymmetricBinding.senderPrivateKey);
    Signature signatureResult = check addSignature(signature, utAsymmetricBinding.signatureAlgorithm, signedData);
    Encryption encryption = check new();
    byte[] encryptData = check encryption.encryptData(check getEnvelopeBody(utAsymmetricBinding.envelope),
                                                      utAsymmetricBinding.encryptionAlgorithm,
                                                      utAsymmetricBinding.receiverPublicKey);
    Encryption encryptionResult = check addEncryption(encryption, utAsymmetricBinding.encryptionAlgorithm,
                                                      encryptData);
    UsernameToken usernameToken = addUsernameToken(wSSecurityHeader, utAsymmetricBinding.username,
                                                   utAsymmetricBinding.password,
                                                   utAsymmetricBinding.passwordType, SIGN_AND_ENCRYPT);
    return generateEnvelope(usernameToken, encryptionResult, signatureResult);
}

# Apply asymmetric binding security policy with X509 token to the SOAP envelope.
# 
# + x509AsymmetricBinding - The `X509AsymmetricBindingConfig` record with the required parameters
# + return - A `xml` type of SOAP envelope if the security binding is successfully added or else `wssec:Error`
public function applyX509AsymmetricBinding(*X509AsymmetricBindingConfig x509AsymmetricBinding) returns xml|Error {
    Document document = check new(x509AsymmetricBinding.envelope);
    WSSecurityHeader wSSecurityHeader = check addSecurityHeader(document);
    Signature signature = check new();
    byte[] signedData = check signature.signData(check getEnvelopeBody(x509AsymmetricBinding.envelope), 
                                                 x509AsymmetricBinding.signatureAlgorithm,
                                                 x509AsymmetricBinding.senderPrivateKey);
    Signature signatureResult = check addSignature(signature, x509AsymmetricBinding.signatureAlgorithm, signedData);
    Encryption encryption = check new();
    byte[] encryptData = check encryption.encryptData(check getEnvelopeBody(x509AsymmetricBinding.envelope),
                                                      x509AsymmetricBinding.encryptionAlgorithm,
                                                      x509AsymmetricBinding.receiverPublicKey);
    Encryption encryptionResult = check addEncryption(encryption, x509AsymmetricBinding.encryptionAlgorithm,
                                                      encryptData);
    UsernameToken usernameToken = addUsernameToken(wSSecurityHeader, x509AsymmetricBinding.username,
                                                   x509AsymmetricBinding.password,
                                                   x509AsymmetricBinding.passwordType, SIGN_AND_ENCRYPT);
    usernameToken = check addX509Token(x509AsymmetricBinding.x509Token, usernameToken);
    return generateEnvelope(usernameToken, encryptionResult, signatureResult);
}
