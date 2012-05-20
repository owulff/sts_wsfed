package demo.sts;

import java.security.Principal;

import org.apache.cxf.sts.IdentityMapper;
import org.apache.ws.security.CustomTokenPrincipal;

/**
 * A test implementation of IdentityMapper.
 */
public class DemoIdentityMapper implements IdentityMapper {

    /**
     * Map a principal in the source realm to the target realm
     * @param sourceRealm the source realm of the Principal
     * @param sourcePrincipal the principal in the source realm
     * @param targetRealm the target realm of the Principal
     * @return the principal in the target realm
     */
    public Principal mapPrincipal(String sourceRealm, Principal sourcePrincipal, String targetRealm) {
        if ("REALMA".equals(sourceRealm)) {
            String name = sourcePrincipal.getName().toUpperCase();
            return new CustomTokenPrincipal(name);
        } else if ("REALMB".equals(sourceRealm)) {
            String name = sourcePrincipal.getName().toLowerCase();
            return new CustomTokenPrincipal(name);
        }
        return null;
    }

}
