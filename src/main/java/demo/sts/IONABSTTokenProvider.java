
package demo.sts;

import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Level;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.phase.PhaseInterceptorChain;
import org.apache.cxf.security.transport.TLSSessionInfo;
import org.apache.cxf.sts.request.ReceivedToken;
import org.apache.cxf.sts.token.provider.TokenProvider;
import org.apache.cxf.sts.token.provider.TokenProviderParameters;
import org.apache.cxf.sts.token.provider.TokenProviderResponse;
import org.apache.cxf.ws.security.sts.provider.STSException;
import org.apache.cxf.ws.security.sts.provider.model.secext.UsernameTokenType;
import org.apache.geronimo.mail.util.Base64;
import org.apache.ws.security.SAMLTokenPrincipal;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.util.UUIDGenerator;

/**
 * A TokenProvider implementation that creates a IONA SSO BinarySecurityToken.
 */
public class IONABSTTokenProvider implements TokenProvider {

	private static final String TOKEN_TYPE = "http://schemas.iona.com/security/IONASSOToken";
	private static final String BASE64_NS = WSConstants.SOAPMESSAGE_NS
			+ "#Base64Binary";
	
	private static final Logger LOG = LoggerFactory.getLogger(IONABSTTokenProvider.class);
	
	private String realm;

	@Override
	public boolean canHandleToken(String tokenType) {
		LOG.debug("Tokentype " + tokenType);
		if (TOKEN_TYPE.equals(tokenType)) {
			return true;
		}
		return false;
	}
	
	@Override
	public boolean canHandleToken(String tokenType, String realm) {
		if (LOG.isDebugEnabled()) {
			LOG.debug("Tokentype " + tokenType + " Realm: " + realm);
		}
		if (TOKEN_TYPE.equals(tokenType) && realm.equalsIgnoreCase(this.realm) ) {
			return true;
		}
		return false;
	}
	
	public void setRealm(String realm) {
		this.realm = realm;
	}
	
	public String getRealm() {
		return this.realm;
	}
	

	@Override
	public TokenProviderResponse createToken(
			TokenProviderParameters tokenParameters) {
		
		ReceivedToken receivedToken = tokenParameters.getTokenRequirements().getOnBehalfOf();
		
		try {
			Document doc = DOMUtils.createDocument();

			String id = "BST-" + UUIDGenerator.getUUID();
			BinarySecurity bst = new BinarySecurity(doc);
			bst.addWSSENamespace();
			bst.addWSUNamespace();
			bst.setID(id);
			bst.setValueType(TOKEN_TYPE);
			bst.setEncodingType(BASE64_NS);
			String tokenValue = new StringBuffer().append(realm).append("_").append(UUIDGenerator.getUUID()).toString();
			bst.setToken(tokenValue.getBytes());
			
			TokenProviderResponse response = new TokenProviderResponse();
			response.setToken(bst.getElement());
			response.setTokenId(id);

			return response;
		} catch (STSException e) {
			throw e;
		} catch (Exception e) {
			LOG.warn("Unexpected excpetion occured", e);
			throw new STSException("Can't create BinarySecurityToken", e);
		}
	}

	
}
