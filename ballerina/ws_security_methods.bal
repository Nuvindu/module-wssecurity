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
    Encryption encrypt = check new ();
    return encrypt.decryptData(cipherText, encryptionAlgorithm, key);
}

function addSignature(Signature sign, string signatureAlgorithm, byte[] signature) returns Signature|Error {
    sign.setSignatureAlgorithm(signatureAlgorithm);
    sign.setSignatureValue(signature);
    return sign;
}

function addEncryption(Encryption encrypt, string encryptionAlgorithm, byte[] encryption) returns Encryption|Error {
    encrypt.setEncryptionAlgorithm(encryptionAlgorithm);
    encrypt.setEncryptedData(encryption);
    return encrypt;
}

function addUsernameToken(WSSecurityHeader wsSecHeader, string username, string password,
        PasswordType passwordType, AuthType authType = NONE) returns UsernameToken {
    UsernameToken usernameToken = new (wsSecHeader, username, password, passwordType);
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
            return check xml:fromString(regex:replace(envelope, string `<?.*?><`, "<"));
        } on fail var e {
            return error Error(e.message());
        }
    }
    if token is UsernameToken {
        string envelope = check token.populateHeaderData(token.getUsername(), token.getPassword(), token.getPasswordType(),
                                                         encryption, signature, token.getAuthType());
        do {
            return check xml:fromString(regex:replace(envelope, string `<?.*?><`, "<"));
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
# + timestampToken - The `TSRecord` record with the required parameters
# + return - A `xml` type of SOAP envelope if the security binding is successfully added or else `wssec:Error`
public function applyTimestampToken(*TimestampTokenConfig timestampToken) returns xml|Error {
    if timestampToken.timeToLive <= 0 {
        return error Error("Invalid value for `timeToLive`");
    }
    Document document = check new (timestampToken.envelope);
    WSSecurityHeader wsSecurityHeader = check addSecurityHeader(document);
    WsSecurity wsSecurity = new;
    string envelope = check wsSecurity.applyTimestampPolicy(wsSecurityHeader, timestampToken.timeToLive);
    do {
        return check xml:fromString(regex:replace(envelope, string `<?.*?><`, "<"));
    } on fail var e {
        return error Error(e.message());
    }
}

# Apply username token security policy to the SOAP envelope.
#
# + usernameToken - The `UsernameTokenConfig` record with the required parameters
# + return - A `xml` type of SOAP envelope if the security binding is successfully added or else `wssec:Error`
public function applyUsernameToken(*UsernameTokenConfig usernameToken) returns xml|Error {
    Document document = check new (usernameToken.envelope);
    WSSecurityHeader wsSecurityHeader = check addSecurityHeader(document);
    WsSecurity wsSecurity = new;
    string envelope = check wsSecurity.applyUtPolicy(wsSecurityHeader, usernameToken.username,
                                                     usernameToken.password, usernameToken.passwordType);
    do {
        return check xml:fromString(regex:replace(envelope, string `<?.*?><`, "<"));
    } on fail var e {
        return error Error(e.message());
    }
}

# Apply symmetric binding security policy with username token to the SOAP envelope.
#
# + symmetricBinding - The `UtSymmetricBindingConfig` record with the required parameters
# + return - A `xml` type of SOAP envelope if the security binding is successfully added or else `wssec:Error`
public function applySymmetricBinding(*SymmetricBindingConfig symmetricBinding) returns xml|Error {
    xml envelope = symmetricBinding.envelope;
    Document document = check new (symmetricBinding.envelope);
    WSSecurityHeader wsSecurityHeader = check addSecurityHeader(document);
    if symmetricBinding.signatureAlgorithm !is () {
        Signature signature = check new ();
        byte[] signedData = check signature.signData(check getEnvelopeBody(envelope),
                                                     <SignatureAlgorithm>symmetricBinding.signatureAlgorithm,
                                                     symmetricBinding.symmetricKey);
        Signature signatureResult = check addSignature(signature,
                                                       <SignatureAlgorithm>symmetricBinding.signatureAlgorithm,
                                                       signedData);
        WsSecurity wsSecurity = new;
        string securedEnvelope = check wsSecurity.applySignatureOnlyPolicy(wsSecurityHeader, signatureResult,
                                                                           symmetricBinding.x509Token);
        do {
            envelope = check xml:fromString(regex:replace(securedEnvelope, string `<?.*?><`, "<"));
        } on fail var e {
            return error Error(e.message());
        }
    }
    if symmetricBinding.encryptionAlgorithm !is () {
        Encryption encryption = check new ();
        byte[] encryptData = check encryption.encryptData(check getEnvelopeBody(envelope),
                                                          <EncryptionAlgorithm>symmetricBinding.encryptionAlgorithm,
                                                          symmetricBinding.symmetricKey);
        Encryption encryptionResult = check addEncryption(encryption,
                                                          <EncryptionAlgorithm>symmetricBinding.encryptionAlgorithm,
                                                          encryptData);
        WsSecurity wsSecurity = new;
        string securedEnvelope = check wsSecurity.applyEncryptionOnlyPolicy(wsSecurityHeader, encryptionResult);
        do {
            envelope = check xml:fromString(regex:replace(securedEnvelope, string `<?.*?><`, "<"));
        } on fail var e {
            return error Error(e.message());
        }
    }
    return envelope;
}

# Apply asymmetric binding security policy with X509 token to the SOAP envelope.
#
# + asymmetricBinding - The `X509AsymmetricBindingConfig` record with the required parameters
# + return - A `xml` type of SOAP envelope if the security binding is successfully added or else `wssec:Error`
public function applyAsymmetricBinding(*AsymmetricBindingConfig asymmetricBinding) returns xml|Error {
    xml envelope = asymmetricBinding.envelope;
    Document document = check new (asymmetricBinding.envelope);
    WSSecurityHeader wsSecurityHeader = check addSecurityHeader(document);
    if asymmetricBinding.signatureAlgorithm !is () {
        Signature signature = check new ();
        byte[] signedData = check signature.signData(check getEnvelopeBody(asymmetricBinding.envelope),
                                                     <SignatureAlgorithm>asymmetricBinding.signatureAlgorithm,
                                                     asymmetricBinding.senderPrivateKey);
        Signature signatureResult = check addSignature(signature,
                                                       <SignatureAlgorithm>asymmetricBinding.signatureAlgorithm,
                                                       signedData);
        WsSecurity wsSecurity = new;
        string securedEnvelope = check wsSecurity.applySignatureOnlyPolicy(wsSecurityHeader, signatureResult,
                                                                           asymmetricBinding.x509Token);
        do {
            envelope = check xml:fromString(regex:replace(securedEnvelope, string `<?.*?><`, "<"));
        } on fail var e {
            return error Error(e.message());
        }
    }
    if asymmetricBinding.encryptionAlgorithm !is () {
        Encryption encryption = check new ();
        byte[] encryptData = check encryption.encryptData(check getEnvelopeBody(asymmetricBinding.envelope),
                                                          <EncryptionAlgorithm>asymmetricBinding.encryptionAlgorithm,
                                                          asymmetricBinding.receiverPublicKey);
        Encryption encryptionResult = check addEncryption(encryption,
                                                          <EncryptionAlgorithm>asymmetricBinding.encryptionAlgorithm,
                                                          encryptData);
        WsSecurity wsSecurity = new;
        string securedEnvelope = check wsSecurity.applyEncryptionOnlyPolicy(wsSecurityHeader, encryptionResult);
        do {
            envelope = check xml:fromString(regex:replace(securedEnvelope, string `<?.*?><`, "<"));
        } on fail var e {
            return error Error(e.message());
        }
    }
    return envelope;
}
