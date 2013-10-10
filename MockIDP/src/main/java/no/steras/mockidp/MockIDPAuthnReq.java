package no.steras.mockidp;

import java.io.IOException;
import java.io.Writer;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.ConfigurationException;

public class MockIDPAuthnReq extends HttpServlet {

	public static String userId;
	public static String secLevel;
	public static String authnReqId;
	public static String relayState;

	static {
		// Init OpenSAML
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			throw new RuntimeException(e);
		}

	}

	@Override
	protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
		Writer w = resp.getWriter();
		resp.setContentType("text/html");
		AuthnRequest authnRequest = unMarshallAuthnRequest(req);
		authnReqId = authnRequest.getID();

		relayState = req.getParameter("RelayState");

		w.append("<html>" + "<head></head>" + "<body> <form method=\"POST\">" + "Bruker ID: <input type=\"text\" name=\"username\" /> " + "<br/>"
				+ "Security level: <input type=\"text\" name=\"secLevel\" value=\"3\"/> " + "<br/>" + "<input type=\"submit\" value=\"Login\"/>" + "</form>"
				+ "</body>" + "</html>");

	}

	private AuthnRequest unMarshallAuthnRequest(final HttpServletRequest request) {
		HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();
		BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject> context = new BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject>();
		context.setInboundMessageTransport(new HttpServletRequestAdapter(request));
		try {
			decoder.decode(context);
		} catch (MessageDecodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (org.opensaml.xml.security.SecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return (AuthnRequest)context.getInboundMessage();
	}

	@Override
	protected void doPost(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {

		userId = req.getParameter("username");
		secLevel = req.getParameter("secLevel");
		try {
			resp.sendRedirect(MockIDPSPMetadata.getSpConsumerUrl() + "?SAMLart=AAQAAMFbLinlXaCM%2BFIxiDwGOLAy2T71gbpO7ZhNzAgEANlB90ECfpNEVLg%3D&RelayState="
					+ relayState);
		} catch (MetadataProviderException e) {
			throw new RuntimeException(e);
		}
	}
}
