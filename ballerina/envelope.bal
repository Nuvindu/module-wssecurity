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

public function getEncryptedData(xml envelope) returns byte[]|Error {
    Document document = check new (envelope);
    return document.getEncryptedData();
}

public function getSignatureData(xml envelope) returns byte[]|Error {
    Document document = check new (envelope);
    return document.getSignatureData();
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

public function applyTimestampToken(*TSRecord tsRecord) returns xml|Error {
    Document document = check new(tsRecord.envelope);
    WSSecurityHeader wSSecurityHeader = check addSecurityHeader(document);
    TimestampToken timestampToken = check addTimestampToken(wSSecurityHeader, tsRecord.timeToLive);
    return check generateEnvelope(timestampToken);
}

public function applyUsernameToken(*UTRecord utRecord) returns xml|Error {
    Document document = check new(utRecord.envelope);
    WSSecurityHeader wSSecurityHeader = check addSecurityHeader(document);
    UsernameToken usernameToken = addUsernameToken(wSSecurityHeader, utRecord.username,
                                                    utRecord.password, utRecord.passwordType, NONE);
    return generateEnvelope(usernameToken);
}

public function applyX509Token(*X509Record x509Record) returns xml|Error {
    Document document = check new(x509Record.envelope);
    WSSecurityHeader wSSecurityHeader = check addSecurityHeader(document);
    UsernameToken usernameToken = addUsernameToken(wSSecurityHeader, x509Record.username, x509Record.password,
                                                    x509Record.passwordType, NONE);
    UsernameToken usernameTokenWithX509 = check addX509Token(x509Record.x509Token, usernameToken);
    return generateEnvelope(usernameTokenWithX509);
}

public function applyUTSignature(*UTSignature utSignature) returns xml|Error {
    Document document = check new(utSignature.envelope);
    WSSecurityHeader wSSecurityHeader = check addSecurityHeader(document);
    Signature signature = check new();
    byte[] signedData = check signature.signData(check getEnvelopeBody(utSignature.envelope), 
                                                    utSignature.signatureAlgorithm, utSignature.signatureKey);
    Signature signatureResult = check addSignature(signature, utSignature.signatureAlgorithm, signedData);
    UsernameToken usernameToken = addUsernameToken(wSSecurityHeader, utSignature.username, utSignature.password,
                                                   utSignature.passwordType, SIGNATURE);
    X509Token|string? x509Token = utSignature.x509Token;
    if x509Token !is () {
        usernameToken = check addX509Token(x509Token, usernameToken);
    }
    return check generateEnvelope(usernameToken, signature = signatureResult);
}

public function applyUTEncryption(*UTEncryption utEncryption) returns xml|Error {
    Document document = check new(utEncryption.envelope);
    WSSecurityHeader wSSecurityHeader = check addSecurityHeader(document);
    Encryption encryption = check new();
    byte[] encryptData = check encryption.encryptData(check getEnvelopeBody(utEncryption.envelope),
                                                      utEncryption.encryptionAlgorithm,
                                                      utEncryption.encryptionKey);
    Encryption encryptionResult = check addEncryption(encryption, utEncryption.encryptionAlgorithm, encryptData);
    UsernameToken usernameToken = addUsernameToken(wSSecurityHeader, utEncryption.username, utEncryption.password,
                                                   utEncryption.passwordType, ENCRYPT);
    X509Token|string? x509Token = utEncryption.x509Token;
    if x509Token !is () {
        usernameToken = check addX509Token(x509Token, usernameToken);
    }
    return generateEnvelope(usernameToken, encryptionResult);
}

public function applyUTSignAndEncrypt(*UTSignAndEncrypt utSignAndEncrypt) returns xml|Error {
    Document document = check new(utSignAndEncrypt.envelope);
    WSSecurityHeader wSSecurityHeader = check addSecurityHeader(document);
    Signature signature = check new();
    byte[] signedData = check signature.signData(check getEnvelopeBody(utSignAndEncrypt.envelope), 
                                                 utSignAndEncrypt.signatureAlgorithm,
                                                 utSignAndEncrypt.signatureKey);
    Signature signatureResult = check addSignature(signature, utSignAndEncrypt.signatureAlgorithm, signedData);
    Encryption encryption = check new();
    byte[] encryptData = check encryption.encryptData(check getEnvelopeBody(utSignAndEncrypt.envelope),
                                                      utSignAndEncrypt.encryptionAlgorithm,
                                                      utSignAndEncrypt.encryptionKey);
    Encryption encryptionResult = check addEncryption(encryption, utSignAndEncrypt.encryptionAlgorithm, encryptData);
    UsernameToken usernameToken = addUsernameToken(wSSecurityHeader, utSignAndEncrypt.username,
                                                    utSignAndEncrypt.password,
                                                    utSignAndEncrypt.passwordType, SIGN_AND_ENCRYPT);
    X509Token|string? x509Token = utSignAndEncrypt.x509Token;
    if x509Token !is () {
        usernameToken = check addX509Token(x509Token, usernameToken);
    }
    return generateEnvelope(usernameToken, encryptionResult, signatureResult);
}

public function applySymmetricBinding(*UTSymmetricBinding utSymmetricBinding) returns xml|Error {
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
    X509Token|string? x509Token = utSymmetricBinding.x509Token;
    if x509Token !is () {
        usernameToken = check addX509Token(x509Token, usernameToken);
    }
    return generateEnvelope(usernameToken, encryptionResult, signatureResult);
}

public function applyAsymmetricBinding(*UTAsymmetricBinding utAsymmetricBinding) returns xml|Error {
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
    Encryption encryptionResult = check addEncryption(encryption, utAsymmetricBinding.encryptionAlgorithm, encryptData);
    UsernameToken usernameToken = addUsernameToken(wSSecurityHeader, utAsymmetricBinding.username,
                                                    utAsymmetricBinding.password,
                                                    utAsymmetricBinding.passwordType, SIGN_AND_ENCRYPT);
    X509Token|string? x509Token = utAsymmetricBinding.x509Token;
    if x509Token !is () {
        usernameToken = check addX509Token(x509Token, usernameToken);
    }
    return generateEnvelope(usernameToken, encryptionResult, signatureResult);
}
