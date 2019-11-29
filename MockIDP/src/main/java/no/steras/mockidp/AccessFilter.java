package no.steras.mockidp;

import java.io.IOException;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.encryption.Encrypter;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.ws.soap.client.SOAPMessageContext;
import org.opensaml.ws.soap.client.http.HttpClientBuilder;
import org.opensaml.ws.soap.client.http.HttpSOAPClient;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.encryption.EncryptionParameters;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.encryption.KeyEncryptionParameters;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.KeyStoreCredentialResolver;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AccessFilter implements Filter {
  private static final String KEY_ENTRY_ID = null;
  private static final String KEY_STORE_ENTRY_PASSWORD = null;
  private static Logger logger = LoggerFactory
      .getLogger(AccessFilter.class);

  @Override
  public void doFilter(ServletRequest request,
      ServletResponse response, FilterChain chain) throws IOException,
      ServletException {
    HttpServletRequest httpServletRequest = (HttpServletRequest) request;
    HttpServletResponse httpServletResponse = (HttpServletResponse) response;

    if (httpServletRequest.getSession().getAttribute(
        SPConstants.AUTHENTICATED_SESSION_ATTRIBUTE) != null) {
      chain.doFilter(request, response);
    } else {
      setGotoURLOnSession(httpServletRequest);
      redirectUserForAuthentication(httpServletResponse);
    }

    AuthnRequest authnRequest = OpenSAMLUtils
        .buildSAMLObject(AuthnRequest.class);
    AuthnRequest artifactResolve = OpenSAMLUtils
        .buildSAMLObject(AuthnRequest.class);

    RequestedAuthnContext requestedAuthnContext = OpenSAMLUtils
        .buildSAMLObject(RequestedAuthnContext.class);

    BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject> context = new BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject>();
    HttpServletResponse httpServletResponse = null;

    HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
    encoder.encode(context);

    Envelope envelope = OpenSAMLUtils.buildSAMLObject(Envelope.class);
    Body body = OpenSAMLUtils.buildSAMLObject(Body.class);

    body.getUnknownXMLObjects().add(artifactResolve);

    envelope.setBody(body);

    HttpClientBuilder clientBuilder = new HttpClientBuilder();
    HttpSOAPClient soapClient = new HttpSOAPClient(
        clientBuilder.buildClient(), new BasicParserPool());

    SOAPMessageContext soapContext;

    Assertion object = null;
    Assertion assertion = null;
    KeyStore keystore;

    Map<String, String> passwordMap = new HashMap<String, String>();
    passwordMap.put(KEY_ENTRY_ID, KEY_STORE_ENTRY_PASSWORD);
    KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(
        keystore, passwordMap);

    Signature signature;
    SignableSAMLObject signableXMLObject;
    signableXMLObject.setSignature(signature);

    Configuration.getMarshallerFactory().getMarshaller(object)
        .marshall(object);

    Signer.signObject(signature);

    if (!assertion.isSigned()) {
      throw new RuntimeException("The SAML Assertion was not signed");
    }

    Credential credential;
    SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
    profileValidator.validate(assertion.getSignature());

    SignatureValidator sigValidator = new SignatureValidator(credential);
    sigValidator.validate(assertion.getSignature());

    EncryptionParameters encryptionParameters = new EncryptionParameters();
    encryptionParameters
        .setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);

    KeyEncryptionParameters keyEncryptionParameters = new KeyEncryptionParameters();
    keyEncryptionParameters.setEncryptionCredential(SPCredentials
        .getCredential());
    keyEncryptionParameters
        .setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);

    Encrypter encrypter = new Encrypter(encryptionParameters,
        keyEncryptionParameters);

    encrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);

    EncryptedAssertion encryptedAssertion = encrypter
        .encrypt(assertion);

    StaticKeyInfoCredentialResolver keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(
        SPCredentials.getCredential());

    Decrypter decrypter = new Decrypter(null,
        keyInfoCredentialResolver, new InlineEncryptedKeyResolver());
    
    decrypter.decrypt(encryptedAssertion);
  }

  private String getIPDArtifactResloveDestination() {
    // TODO Auto-generated method stub
    return null;
  }

  private String getIPDSSODestination() {
    // TODO Auto-generated method stub
    return null;
  }

  private RequestedAuthnContext buildRequestedAuthnContext() {
    // TODO Auto-generated method stub
    return null;
  }

  private String getSPIssuerValue() {
    // TODO Auto-generated method stub
    return null;
  }

  private String getAssertionConsumerEndpoint() {
    // TODO Auto-generated method stub
    return null;
  }

  private void redirectUserForAuthentication(
      HttpServletResponse httpServletResponse) {
    // TODO Auto-generated method stub

  }

  private void setGotoURLOnSession(HttpServletRequest httpServletRequest) {
    // TODO Auto-generated method stub

  }

  @Override
  public void destroy() {
    // TODO Auto-generated method stub

  }

  @Override
  public void init(FilterConfig arg0) throws ServletException {
    // TODO Auto-generated method stub

  }
}
