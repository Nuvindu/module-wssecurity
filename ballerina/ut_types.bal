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

public enum AuthenticationType {
    NONE = "NONE",
    SIGN = "SIGNATURE",
    ENCRYPT = "ENCRYPT",
    SIGN_AND_ENCRYPT = "SIGN_AND_ENCRYPT"
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
