package no.steras.mockidp;

import java.io.File;

import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.security.MetadataCredentialResolverFactory;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.criteria.EntityIDCriteria;

public class MockIDPSPMetadata {
	private static FilesystemMetadataProvider spMetaDataProvider;

	public MockIDPSPMetadata() {

	}

	static {
		try {

			try {
				DefaultBootstrap.bootstrap();
			} catch (ConfigurationException e) {
				throw new RuntimeException(e);
			}
			spMetaDataProvider = new FilesystemMetadataProvider(new File(MockIDPProperties.getSpMetadataLocation()));
			spMetaDataProvider.setRequireValidMetadata(true);

			BasicParserPool ppMgr = new BasicParserPool();
			ppMgr.setNamespaceAware(true);
			spMetaDataProvider.setParserPool(new BasicParserPool());

			spMetaDataProvider.initialize();

		} catch (MetadataProviderException e) {
			throw new RuntimeException(e);
		}
	}

	public static String getSpConsumerUrl() throws MetadataProviderException {
		// Get the request address from ID-porten meta data
		AssertionConsumerService assertionConsumerService = null;
		for (AssertionConsumerService acs : getEntityDescriptor().getSPSSODescriptor(SAMLConstants.SAML20P_NS).getAssertionConsumerServices()) {
			if (acs.getBinding().equals(SAMLConstants.SAML2_ARTIFACT_BINDING_URI)) {
				assertionConsumerService = acs;
			}
		}
		return assertionConsumerService.getLocation();
	}

	public static String getAudienceUri() {
		return MockIDPProperties.getSpEntityId();
	}

	public static Credential getSpCredentials() throws SecurityException {
		MetadataCredentialResolverFactory credentialResolverFactory = MetadataCredentialResolverFactory.getFactory();
		MetadataCredentialResolver credentialResolver = credentialResolverFactory.getInstance(spMetaDataProvider);

		CriteriaSet criteriaSet = new CriteriaSet();
		criteriaSet.add(new MetadataCriteria(SPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS));
		criteriaSet.add(new EntityIDCriteria(MockIDPProperties.getSpEntityId()));

		return credentialResolver.resolveSingle(criteriaSet);
	}

	private static EntityDescriptor getEntityDescriptor() throws MetadataProviderException {
		return spMetaDataProvider.getEntityDescriptor(MockIDPProperties.getSpEntityId());
	}
}
