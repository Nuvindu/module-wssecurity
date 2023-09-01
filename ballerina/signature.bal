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
import ballerina/random;
import ballerina/crypto;
import ballerina/jballerina.java;

public class Signature {

    private handle nativeSignature;
    private byte[16] key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    private byte[16] initialVector = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    public function init() returns Error? {
        foreach int i in 0...15 {
            self.key[i] = <byte>(check random:createIntInRange(0, 255));
        } on fail var e {
        	return error(e.message());
        }
        foreach int i in 0...15 {
            self.initialVector[i] = <byte>(check random:createIntInRange(0, 255));
        } on fail var e {
        	return error(e.message());
        }
        self.nativeSignature = newSignature();
    }

    public function signData(string dataString, SignatureAlgorithm signatureAlgorithm, 
                             crypto:PrivateKey privateKey) returns byte[]|Error {
        byte[] data = dataString.toBytes();
        do {
            match signatureAlgorithm {
                RSA_SHA1 => {
                    return check crypto:signRsaSha1(data, privateKey);
                }
                RSA_SHA256 => {
                    return check crypto:signRsaSha256(data, privateKey);
                }
                _ => {
                    return error("Invalid signature!");
                }
            }
        } on fail var e {
        	return error(e.message());
        }
    }

    public function verifySignature(byte[] data, byte[] signature, crypto:PublicKey publicKey, 
                                    SignatureAlgorithm signatureAlgorithm = RSA_SHA256) returns boolean|Error {
        do {
            match signatureAlgorithm {
                RSA_SHA256 => {
                    return check crypto:verifyRsaSha256Signature(data, signature, publicKey);
                }
                RSA_SHA1 => {
                    return check crypto:verifyRsaSha1Signature(data, signature, publicKey);
                }
                _ => {
                    return error("Invalid signature!");
                }
            }
	        
        } on fail var e {
        	return error(e.message());
        }
    }

    public function setSignatureAlgorithm(string signatureAlgorithm) = @java:Method {
        'class: "org.wssecurity.Signature"
    } external;

    public function setSignatureValue(byte[] signatureValue) = @java:Method {
        'class: "org.wssecurity.Signature"
    } external;

    public function getSignatureValue() returns byte[] = @java:Method {
        'class: "org.wssecurity.Signature"
    } external;
}

function newSignature() returns handle = @java:Constructor {
    'class: "org.wssecurity.Signature"
} external;