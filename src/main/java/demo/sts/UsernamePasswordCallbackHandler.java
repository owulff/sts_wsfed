/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package demo.sts;

import java.io.IOException;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import org.apache.ws.security.WSPasswordCallback;

public class UsernamePasswordCallbackHandler implements CallbackHandler {

    private Map<String, String> passwords;

    public void setPasswords(Map<String, String> passwords) {
        this.passwords = passwords;
    }

    public Map<String, String> getPasswords() {
        return passwords;
    }

    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

        if (getPasswords() == null || getPasswords().size() == 0) {
            return;
        }

        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof WSPasswordCallback) { // CXF
                WSPasswordCallback pc = (WSPasswordCallback) callbacks[i];

                String pw = getPasswords().get(pc.getIdentifier());
                pc.setPassword(pw);
            }
        }
    }


}
