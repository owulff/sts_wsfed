package demo.sts;

import java.util.StringTokenizer;

import javax.xml.ws.WebServiceContext;

import org.apache.cxf.sts.RealmParser;
import org.apache.cxf.ws.security.sts.provider.STSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UriRealmParser implements RealmParser {

	public enum REALMS { REALMA, REALMB };
	
	private static final Logger LOG = LoggerFactory.getLogger(UriRealmParser.class);
	
	@Override
	public String parseRealm(WebServiceContext context) throws STSException {
        String url = (String)context.getMessageContext().get("org.apache.cxf.request.url");
        
        // Get the realm of the request url
        // Example: https://localhost:8443/opensso/REALMA/STSServiceTransport
        // realm = INFO
        StringTokenizer st = new StringTokenizer(url, "/");
        String realm = null;
        int count = st.countTokens();
        if (count <= 1) return null;
        count--;
        for (int i = 0; i < count; i++) {
        	realm = st.nextToken();
        }
        realm = realm.toUpperCase();
        try {
        	REALMS.valueOf(realm);
        } catch (IllegalArgumentException ex) {
        	LOG.warn("Unknown realm: " + realm);
        	return null;
        }
        return realm;
	}

}
