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

package org.wssec;

import io.ballerina.runtime.api.creators.ErrorCreator;
import io.ballerina.runtime.api.creators.ValueCreator;
import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BArray;
import io.ballerina.runtime.api.values.BHandle;
import io.ballerina.runtime.api.values.BObject;
import io.ballerina.runtime.api.values.BXml;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import static org.wssec.Constants.NATIVE_DOCUMENT;
import static org.wssec.Constants.SOAP_BODY_TAG;
import static org.wssec.Utils.createError;

public class DocumentBuilder {
    private final Document document;

    public DocumentBuilder(BXml xmlPayload) {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        try {
            this.document = factory.newDocumentBuilder()
                    .parse(new InputSource(new StringReader(xmlPayload.toString())));
        } catch (SAXException | IOException | ParserConfigurationException e) {
            throw createError(e.getMessage());
        }
    }

    protected DocumentBuilder(Document document) {
        this.document = document;
    }

    public static Object getDocument(BObject documentBuilder) {
        BHandle handle = (BHandle) documentBuilder.get(StringUtils.fromString(NATIVE_DOCUMENT));
        DocumentBuilder docBuilder = (DocumentBuilder) handle.getValue();
        Document document = docBuilder.getNativeDocument();
        try {
            return StringUtils.fromString(convertDocumentToString(document));
        } catch (Exception e) {
            return ErrorCreator.createError(StringUtils.fromString(e.getMessage()));
        }
    }

    public static Object getEnvelopeBody(BObject documentBuilder) {
        BHandle handle = (BHandle) documentBuilder.get(StringUtils.fromString(NATIVE_DOCUMENT));
        DocumentBuilder docBuilder = (DocumentBuilder) handle.getValue();
        Document document = docBuilder.getNativeDocument();
        NodeList digestValueList = document.getElementsByTagName(SOAP_BODY_TAG);
        try {
            return StringUtils.fromString(digestValueList.item(0).getFirstChild().getTextContent());
        } catch (Exception e) {
            return ErrorCreator.createError(StringUtils.fromString(e.getMessage()));
        }
    }

    public static BArray getSignatureData(BObject document) {
        BHandle handle = (BHandle) document.get(StringUtils.fromString(NATIVE_DOCUMENT));
        DocumentBuilder docBuilder = (DocumentBuilder) handle.getValue();
        return ValueCreator.createArrayValue(WSSecurityUtils.getSignatureValue(docBuilder.getNativeDocument()));
    }

    public static BArray getEncryptedData(BObject document) {
        BHandle handle = (BHandle) document.get(StringUtils.fromString(NATIVE_DOCUMENT));
        DocumentBuilder docBuilder = (DocumentBuilder) handle.getValue();
        return ValueCreator.createArrayValue(WSSecurityUtils.getEncryptedData(docBuilder.getNativeDocument()));
    }

    protected Document getNativeDocument() {
        return this.document;
    }

    public static String convertDocumentToString(Document doc) throws Exception {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(doc), new StreamResult(writer));
        return writer.toString();
    }
}
