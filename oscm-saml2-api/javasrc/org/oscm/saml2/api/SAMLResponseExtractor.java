/*******************************************************************************
 *                                                                              
 *  Copyright FUJITSU LIMITED 2016                                             
 *                                                                                                                                 
 *  Creation Date: Jun 13, 2013                                                      
 *                                                                              
 *******************************************************************************/

package org.oscm.saml2.api;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamException;
import javax.xml.transform.TransformerException;
import javax.xml.xpath.XPathExpressionException;

import org.apache.commons.codec.binary.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import org.oscm.converter.XMLConverter;
import org.oscm.internal.types.exception.UserIdNotFoundException;
import com.sun.xml.ws.security.opt.impl.incoming.SAMLAssertion;
import com.sun.xml.wss.XWSSecurityException;
import com.sun.xml.wss.saml.util.SAMLUtil;

/**
 * Class for retrieving the userid from a saml:response received from an IdP.
 * 
 * @author farmaki
 * 
 */
public class SAMLResponseExtractor {

    private static final String USER_SAML2_ATTRIBUTE_USERID_XPATH_EXPR = "//*[local-name()='Assertion']" //
            + "//*[local-name()='AttributeStatement']" //
            + "//*[local-name()='Attribute'][@Name='userid']" //
            + "/*[local-name()='AttributeValue']";

    private static final String USER_SAML2_ATTRIBUTE_NAME_XPATH_EXPR = "//*[local-name()='Assertion']" //
            + "//*[local-name()='AttributeStatement']" //
            + "//*[local-name()='Attribute'][@Name='name']" //
            + "/*[local-name()='AttributeValue']";

    private static final String USER_SAML1_ATTRIBUTE_USERID_XPATH_EXPR = "//*[local-name()='Assertion']" //
            + "//*[local-name()='AttributeStatement']" //
            + "//*[local-name()='Attribute'][@AttributeName='userid']" //
            + "/*[local-name()='AttributeValue']";

    private static final String USER_SAML1_ATTRIBUTE_NAME_XPATH_EXPR = "//*[local-name()='Assertion']" //
            + "//*[local-name()='AttributeStatement']" //
            + "//*[local-name()='Attribute'][@AttributeName='name']" //
            + "/*[local-name()='AttributeValue']";

    /**
     * Retrieves the userid from an encoded saml:Response String.
     * 
     * @param encodedSamlResponse
     *            the encoded saml response
     * @return the userid as a String
     * @throws UnsupportedEncodingException
     */
    public String getUserId(String encodedSamlResponse)
            throws UserIdNotFoundException {

        String userId = null;

        try {
            userId = getUserId_decoded(decode(encodedSamlResponse));
        } catch (UnsupportedEncodingException exception) {
            throw new UserIdNotFoundException(
                    String.format(
                            "An exception occurred while Base64-decoding the SAML response:\n%s",
                            encodedSamlResponse),
                    UserIdNotFoundException.ReasonEnum.EXCEPTION_OCCURRED,
                    exception, new String[] { encodedSamlResponse });
        }

        return userId;
    }

    private String getUserId_decoded(String samlResponse)
            throws UserIdNotFoundException {
        String userid = null;

        try {
            Document document = XMLConverter.convertToDocument(samlResponse,
                    true);

            userid = extractUserId(document);
        } catch (XPathExpressionException | ParserConfigurationException
                | SAXException | IOException exception) {
            throw new UserIdNotFoundException(
                    String.format(
                            "An exception occurred while retrieving the userid from the saml response:\n%s",
                            samlResponse),
                    UserIdNotFoundException.ReasonEnum.EXCEPTION_OCCURRED,
                    exception, new String[] { samlResponse });
        }

        if (userid == null || userid.trim().length() == 0) {
            throw new UserIdNotFoundException(
                    String.format(
                            "The userid attribute was not found for the saml response:\n%s",
                            samlResponse),
                    UserIdNotFoundException.ReasonEnum.USERID_ATTRIBUTE_NOT_FOUND,
                    new String[] { samlResponse });

        }
        return userid;
    }

    String extractUserId(Document samlResponse) throws XPathExpressionException {
        String userId = XMLConverter.getNodeTextContentByXPath(samlResponse,
                USER_SAML2_ATTRIBUTE_USERID_XPATH_EXPR);
        if (userId != null) {
            return userId;
        }

        userId = XMLConverter.getNodeTextContentByXPath(samlResponse,
                USER_SAML1_ATTRIBUTE_USERID_XPATH_EXPR);
        if (userId != null) {
            return userId;
        }

        userId = XMLConverter.getNodeTextContentByXPath(samlResponse,
                USER_SAML2_ATTRIBUTE_NAME_XPATH_EXPR);
        if (userId != null) {
            return userId;
        }

        userId = XMLConverter.getNodeTextContentByXPath(samlResponse,
                USER_SAML1_ATTRIBUTE_NAME_XPATH_EXPR);
        return userId;
    }

    public String getUserId(SAMLAssertion samlResponse)
            throws UserIdNotFoundException {
        String samlAssertionString = null;
        try {
            Element samlAssertion = SAMLUtil.createSAMLAssertion(samlResponse
                    .getSamlReader());
            samlAssertionString = XMLConverter.convertToString(samlAssertion,
                    false);
        } catch (XWSSecurityException | XMLStreamException
                | TransformerException exception) {
            throw new UserIdNotFoundException(
                    "An XML exception occurred while processing the SAML response",
                    UserIdNotFoundException.ReasonEnum.EXCEPTION_OCCURRED,
                    exception);
        }
        return getUserId_decoded(samlAssertionString);
    }

    public String decode(String encodedString)
            throws UnsupportedEncodingException {
        byte[] decodedBytes = Base64.decodeBase64(encodedString);
        String decodedString = new String(decodedBytes, "UTF-8");
        return decodedString;
    }
}
