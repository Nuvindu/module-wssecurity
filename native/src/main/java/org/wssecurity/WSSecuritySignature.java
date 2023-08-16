//package org.wssecurity;
//
//import io.ballerina.runtime.api.utils.StringUtils;
//import io.ballerina.runtime.api.values.BHandle;
//import io.ballerina.runtime.api.values.BObject;
//import org.apache.wss4j.common.crypto.Crypto;
//import org.apache.wss4j.common.ext.WSSecurityException;
//import org.apache.wss4j.common.util.UsernameTokenUtil;
//import org.apache.wss4j.dom.handler.RequestData;
//import org.apache.wss4j.dom.message.WSSecSignature;
//
//public class WSSecuritySignature {
//    private WSSecSignature wsSecSignature;
//    String id = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#UsernameToken";
//    public WSSecuritySignature(BObject wsSecHeader) {
//        BHandle handle = (BHandle) wsSecHeader.get(StringUtils.fromString("nativeSecHeader"));
//        WSSecurityHeader wsSecurityHeader = (WSSecurityHeader) handle.getValue();
//        this.wsSecSignature = new WSSecSignature(wsSecurityHeader.getWsSecHeader());
//    }
//
//    private WSSecSignature prepareSignature(RequestData reqData,
//                                            UsernameToken usernameToken) throws WSSecurityException {
//        WSSecSignature sign = new WSSecSignature(reqData.getSecHeader());
//        byte[] salt = UsernameTokenUtil.generateSalt(reqData.isUseDerivedKeyForMAC());
//        sign.setIdAllocator(reqData.getWssConfig().getIdAllocator());
//        sign.setAddInclusivePrefixes(reqData.isAddInclusivePrefixes());
//        sign.setCustomTokenValueType(id);
//        sign.setCustomTokenId(usernameToken.getUsernameToken().getId());
//        sign.setSecretKey(usernameToken.getUsernameToken().getDerivedKey(salt));
//        sign.setKeyIdentifierType(9);
//        sign.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#hmac-sha1");
//        sign.prepare((Crypto) null);
//
//        return sign;
//    }
//}
