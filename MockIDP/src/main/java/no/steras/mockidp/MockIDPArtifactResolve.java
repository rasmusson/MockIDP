package no.steras.mockidp;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.Writer;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.HashMap;
import java.util.Map;

import javax.security.cert.CertificateException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.jdom2.JDOMException;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.encryption.Encrypter;
import org.opensaml.saml2.encryption.Encrypter.KeyPlacement;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.encryption.EncryptionException;
import org.opensaml.xml.encryption.EncryptionParameters;
import org.opensaml.xml.encryption.KeyEncryptionParameters;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.security.Criteria;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.KeyStoreCredentialResolver;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

public class MockIDPArtifactResolve extends HttpServlet {

	@Override
	protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
		Writer w = resp.getWriter();
		resp.setContentType("text/html");
		w.append("<html>" + "<head></head>" + "<body> <form method=\"POST\">" + "Bruker ID: <input type=\"text\" name=\"id\" /> " + "<br/>"
				+ "<input type=\"submit\" value=\"Login\"/>" + "</form>" + "</body>" + "</html>");

	}

	@Override
	protected void doPost(final HttpServletRequest arg0, final HttpServletResponse arg1) throws ServletException, IOException {
		System.out.println("post");
		arg1.setContentType("text/xml");

		try {
			ArtifactResolve artifactResolve = unmarshallArtifactResolve(arg0.getInputStream());

			ArtifactResponse artifactResponse = buildArtifactResponse();
			artifactResponse.setInResponseTo(artifactResolve.getID());

			printSAMLObject(wrapInSOAPEnvelope(artifactResponse), arg1.getWriter());
		} catch (IllegalAccessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (java.security.cert.CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (EncryptionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (MarshallingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (MetadataProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnmarshallingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (XMLParserException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public static ArtifactResolve unmarshallArtifactResolve(final InputStream input) throws IllegalAccessException, UnmarshallingException, XMLParserException {
		BasicParserPool ppMgr = new BasicParserPool();
		ppMgr.setNamespaceAware(true);

		Document soap = ppMgr.parse(input);
		Element soapRoot = soap.getDocumentElement();

		// Get apropriate unmarshaller
		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(soapRoot);

		Envelope soapEnvelope = (Envelope)unmarshaller.unmarshall(soapRoot);
		return (ArtifactResolve)soapEnvelope.getBody().getUnknownXMLObjects().get(0);
	}

	public static org.w3c.dom.Element marshallSAMLObject(final SAMLObject object) throws IllegalAccessException, UnmarshallingException, MarshallingException {
		org.w3c.dom.Element element = null;
		try {
			MarshallerFactory unMarshallerFactory = Configuration.getMarshallerFactory();

			Marshaller marshaller = unMarshallerFactory.getMarshaller(object);

			element = marshaller.marshall(object);
		} catch (ClassCastException e) {
			throw new IllegalArgumentException("The class does not implement the interface XMLObject", e);
		}

		return element;
	}

	private ArtifactResponse buildArtifactResponse() throws IllegalAccessException, NoSuchAlgorithmException, KeyStoreException,
			java.security.cert.CertificateException, CertificateException, IOException, SecurityException, EncryptionException, NoSuchProviderException,
			SignatureException, MarshallingException, MetadataProviderException {
		SecureRandomIdentifierGenerator idGenerator = new SecureRandomIdentifierGenerator();

		ArtifactResponse artifactResponse = buildXMLObjectDefaultName(ArtifactResponse.class);

		Issuer issuer = buildXMLObjectDefaultName(Issuer.class);
		issuer.setValue(MockIDPProperties.getIdpEntityId());
		artifactResponse.setIssuer(issuer);
		artifactResponse.setIssueInstant(new DateTime());
		artifactResponse.setDestination(MockIDPSPMetadata.getSpConsumerUrl());

		artifactResponse.setID(idGenerator.generateIdentifier());

		Status status = buildXMLObjectDefaultName(Status.class);
		StatusCode statusCode = buildXMLObjectDefaultName(StatusCode.class);
		statusCode.setValue(StatusCode.SUCCESS_URI);
		status.setStatusCode(statusCode);
		artifactResponse.setStatus(status);

		Response response = buildXMLObjectDefaultName(Response.class);
		response.setDestination(MockIDPSPMetadata.getSpConsumerUrl());
		response.setIssueInstant(new DateTime());
		response.setID(idGenerator.generateIdentifier());
		response.setInResponseTo(MockIDPAuthnReq.authnReqId);
		Issuer issuer2 = buildXMLObjectDefaultName(Issuer.class);
		issuer2.setValue(MockIDPProperties.getIdpEntityId());

		response.setIssuer(issuer2);

		Status status2 = buildXMLObjectDefaultName(Status.class);
		StatusCode statusCode2 = buildXMLObjectDefaultName(StatusCode.class);
		statusCode2.setValue(StatusCode.SUCCESS_URI);
		status2.setStatusCode(statusCode2);

		response.setStatus(status2);

		artifactResponse.setMessage(response);

		response.getEncryptedAssertions().add(encryptAssertion(buildAssertion()));
		return artifactResponse;
	}

	private Assertion buildAssertion() throws NoSuchAlgorithmException, IllegalAccessException, KeyStoreException, java.security.cert.CertificateException,
			SignatureException, MarshallingException, CertificateException, IOException, SecurityException, MetadataProviderException {
		SecureRandomIdentifierGenerator idGenerator = new SecureRandomIdentifierGenerator();

		Assertion assertion = buildXMLObjectDefaultName(Assertion.class);

		Issuer issuer = buildXMLObjectDefaultName(Issuer.class);
		issuer.setValue(MockIDPProperties.getIdpEntityId());
		assertion.setIssuer(issuer);
		assertion.setIssueInstant(new DateTime());

		assertion.setID(idGenerator.generateIdentifier());

		Subject subject = buildXMLObjectDefaultName(Subject.class);
		assertion.setSubject(subject);

		NameID nameID = buildXMLObjectDefaultName(NameID.class);
		nameID.setFormat(NameIDType.TRANSIENT);
		nameID.setValue("5VkzP/MZ1PMJ62o45/7DdFms9y7K");
		nameID.setSPNameQualifier("steras-openam");
		nameID.setNameQualifier("FakeIdP");

		subject.setNameID(nameID);

		subject.getSubjectConfirmations().add(buildSubjectConfirmation());

		assertion.setConditions(buildConditions());

		assertion.getAttributeStatements().add(buildAttributeStatement());

		assertion.getAuthnStatements().add(buildAuthnStatement());

		signSAMLObject(assertion, getIDPKeyFromKeystore());
		return assertion;
	}

	private SubjectConfirmation buildSubjectConfirmation() throws IllegalAccessException, MetadataProviderException {
		SubjectConfirmation subjectConfirmation = buildXMLObjectDefaultName(SubjectConfirmation.class);
		subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);

		SubjectConfirmationData subjectConfirmationData = buildXMLObjectDefaultName(SubjectConfirmationData.class);
		subjectConfirmationData.setInResponseTo(MockIDPAuthnReq.authnReqId);
		subjectConfirmationData.setNotBefore(new DateTime().minusDays(2));
		subjectConfirmationData.setNotOnOrAfter(new DateTime().plusDays(2));
		subjectConfirmationData.setRecipient(MockIDPSPMetadata.getSpConsumerUrl());

		subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

		return subjectConfirmation;
	}

	private AuthnStatement buildAuthnStatement() throws IllegalAccessException {
		AuthnStatement authnStatement = buildXMLObjectDefaultName(AuthnStatement.class);
		AuthnContext authnContext = buildXMLObjectDefaultName(AuthnContext.class);
		AuthnContextClassRef authnContextClassRef = buildXMLObjectDefaultName(AuthnContextClassRef.class);
		authnContextClassRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
		authnContext.setAuthnContextClassRef(authnContextClassRef);
		authnStatement.setAuthnContext(authnContext);

		authnStatement.setAuthnInstant(new DateTime());

		return authnStatement;
	}

	private Conditions buildConditions() throws IllegalAccessException {
		Conditions conditions = buildXMLObjectDefaultName(Conditions.class);
		conditions.setNotBefore(new DateTime().minusDays(2));
		conditions.setNotOnOrAfter(new DateTime().plusDays(2));
		AudienceRestriction audienceRestriction = buildXMLObjectDefaultName(AudienceRestriction.class);
		Audience audience = buildXMLObjectDefaultName(Audience.class);
		audience.setAudienceURI(MockIDPSPMetadata.getAudienceUri());
		audienceRestriction.getAudiences().add(audience);
		conditions.getAudienceRestrictions().add(audienceRestriction);
		return conditions;
	}

	private AttributeStatement buildAttributeStatement() throws IllegalAccessException {
		AttributeStatement attributeStatement = buildXMLObjectDefaultName(AttributeStatement.class);

		Attribute attributeUserName = buildXMLObjectDefaultName(Attribute.class);

		XSStringBuilder stringBuilder = (XSStringBuilder)Configuration.getBuilderFactory().getBuilder(XSString.TYPE_NAME);
		XSString userNameValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
		userNameValue.setValue(MockIDPAuthnReq.userId);

		attributeUserName.getAttributeValues().add(userNameValue);
		attributeUserName.setName("uid");
		attributeStatement.getAttributes().add(attributeUserName);

		Attribute attributeLevel = buildXMLObjectDefaultName(Attribute.class);
		XSString levelValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
		levelValue.setValue(MockIDPAuthnReq.secLevel);

		attributeLevel.getAttributeValues().add(levelValue);
		attributeLevel.setName("SecurityLevel");
		attributeStatement.getAttributes().add(attributeLevel);

		return attributeStatement;

	}

	private EncryptedAssertion encryptAssertion(final Assertion assertion) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
			IOException, SecurityException, EncryptionException, java.security.cert.CertificateException, NoSuchProviderException {
		Credential keyEncryptionCredential = MockIDPSPMetadata.getSpCredentials();

		EncryptionParameters encParams = new EncryptionParameters();
		encParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);

		KeyEncryptionParameters kekParams = new KeyEncryptionParameters();
		kekParams.setEncryptionCredential(keyEncryptionCredential);
		kekParams.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSA15);
		/*KeyInfoGeneratorFactory kigf = Configuration.getGlobalSecurityConfiguration().getKeyInfoGeneratorManager().getDefaultManager()
				.getFactory(keyEncryptionCredential);
		
		kekParams.setKeyInfoGenerator(kigf.newInstance());*/

		Encrypter samlEncrypter = new Encrypter(encParams, kekParams);
		samlEncrypter.setKeyPlacement(KeyPlacement.INLINE);

		return samlEncrypter.encrypt(assertion);

	}

	private org.w3c.dom.Element getArtifactResolveElement(final InputStream is) throws SAXException, IOException, JDOMException, ParserConfigurationException {

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		DocumentBuilder db = dbf.newDocumentBuilder();
		Document doc = db.parse(is);

		return (org.w3c.dom.Element)doc.getDocumentElement().getFirstChild().getFirstChild();
	}

	public static <T> T buildXMLObjectDefaultName(final Class<T> objectClass) throws IllegalAccessException {
		XMLObjectBuilderFactory builderFaktory = Configuration.getBuilderFactory();

		T genericObject = null;
		try {
			QName defaultName = (QName)objectClass.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
			genericObject = (T)builderFaktory.getBuilder(defaultName).buildObject(defaultName);
		} catch (NoSuchFieldException e) {
			throw new IllegalArgumentException("The class does not have a default element name", e);
		} catch (ClassCastException e) {
			throw new IllegalArgumentException("The class does not implement the interface XMLObject", e);
		}

		return genericObject;
	}

	public void signSAMLObject(final SignableSAMLObject object, final X509Credential credential) throws org.opensaml.xml.signature.SignatureException,
			MarshallingException {
		Signature signature = (Signature)Configuration.getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME)
				.buildObject(Signature.DEFAULT_ELEMENT_NAME);

		signature.setSigningCredential(credential);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

		object.setSignature(signature);

		Configuration.getMarshallerFactory().getMarshaller(object).marshall(object);

		Signer.signObject(signature);
	}

	public static Envelope wrapInSOAPEnvelope(final XMLObject xmlObject) throws IllegalAccessException {
		Envelope envelope = buildXMLObjectDefaultName(Envelope.class);
		Body body = buildXMLObjectDefaultName(Body.class);

		body.getUnknownXMLObjects().add(xmlObject);

		envelope.setBody(body);

		return envelope;
	}

	private X509Credential getIDPKeyFromKeystore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, SecurityException,
			java.security.cert.CertificateException {
		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		InputStream inputStream = MockIDPArtifactResolve.class.getResourceAsStream("/keystore-idp.jks");
		keystore.load(inputStream, "changeit".toCharArray());
		inputStream.close();

		Map<String, String> passwordMap = new HashMap<String, String>();
		passwordMap.put("test", "changeit");
		KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(keystore, passwordMap);

		Criteria criteria = new EntityIDCriteria("test");
		CriteriaSet criteriaSet = new CriteriaSet(criteria);

		return (X509Credential)resolver.resolveSingle(criteriaSet);
	}

	public static void printSAMLObject(final XMLObject object, final PrintWriter writer) {
		try {
			DocumentBuilder builder;
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setNamespaceAware(true);

			builder = factory.newDocumentBuilder();

			org.w3c.dom.Document document = builder.newDocument();
			Marshaller out = Configuration.getMarshallerFactory().getMarshaller(object);
			out.marshall(object, document);

			Transformer transformer = TransformerFactory.newInstance().newTransformer();
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");
			StreamResult result = new StreamResult(writer);
			DOMSource source = new DOMSource(document);
			transformer.transform(source, result);
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		} catch (MarshallingException e) {
			e.printStackTrace();
		} catch (TransformerException e) {
			e.printStackTrace();
		}
	}

}
