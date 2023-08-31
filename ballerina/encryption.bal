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

public class Encryption {

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
    }
    public function encryptData(string dataString) returns byte[]|Error {
        byte[] data = dataString.toBytes();
        do {
	        return check crypto:encryptAesCbc(data, self.key, self.initialVector);
        } on fail var e {
        	return error(e.message());
        }
    }

    public function decryptData(byte[] cipherText) returns byte[]|Error {
        do {
	        return check crypto:decryptAesCbc(cipherText, self.key, self.initialVector);
        } on fail var e {
        	return error(e.message());
        }
    }

}
