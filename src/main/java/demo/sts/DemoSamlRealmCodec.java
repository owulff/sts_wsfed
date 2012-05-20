package demo.sts;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.apache.cxf.sts.token.realm.SAMLRealmCodec;
import org.apache.ws.security.saml.SAMLKeyInfo;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.opensaml.common.SAMLVersion;
import org.opensaml.xml.signature.Signature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DemoSamlRealmCodec implements SAMLRealmCodec {

	private static final Logger LOG = LoggerFactory.getLogger(DemoSamlRealmCodec.class);
	
	@Override
	public String getRealmFromToken(AssertionWrapper assertion) {
		SAMLKeyInfo ki = assertion.getSignatureKeyInfo();
		X509Certificate[] certs = ki.getCerts();
		X500Principal subject = certs[0].getSubjectX500Principal();
		String name = subject.getName();
		String realm = name.substring(name.indexOf("CN=") + 3);
		return realm.toUpperCase();
	}

}
