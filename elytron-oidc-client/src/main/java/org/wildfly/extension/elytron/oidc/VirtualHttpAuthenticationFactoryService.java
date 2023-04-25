/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.extension.elytron.oidc;

import static org.jboss.as.server.security.VirtualDomainUtil.VIRTUAL;

import java.io.ByteArrayInputStream;

import org.jboss.msc.service.Service;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.server.HttpAuthenticationFactory;
import org.wildfly.security.auth.server.MechanismConfiguration;
import org.wildfly.security.auth.server.MechanismConfigurationSelector;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.oidc.OidcClientConfigurationBuilder;
import org.wildfly.security.http.oidc.OidcClientContext;
import org.wildfly.security.http.oidc.OidcMechanismFactory;
import org.wildfly.security.http.oidc.OidcSecurityRealm;

/**
 * A {@link Service} responsible for managing the lifecycle of a virtual {@code HttpAuthenticationFactory}.
 *
 * <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class VirtualHttpAuthenticationFactoryService implements Service<HttpAuthenticationFactory> {

    private final String oidcJsonConfiguration;
    private volatile HttpAuthenticationFactory httpAuthenticationFactory;

    public VirtualHttpAuthenticationFactoryService(String oidcJsonConfiguration) {
        this.oidcJsonConfiguration = oidcJsonConfiguration;
    }

    @Override
    public void start(StartContext context) throws StartException {
        final OidcClientContext oidcClientContext = new OidcClientContext(OidcClientConfigurationBuilder
                .build(new ByteArrayInputStream(oidcJsonConfiguration.getBytes())));
        final HttpServerAuthenticationMechanismFactory virtualMechanismFactory = new OidcMechanismFactory(oidcClientContext);
        final SecurityDomain.Builder virtualDomainBuilder = SecurityDomain.builder()
                .addRealm(VIRTUAL, new OidcSecurityRealm()).build()
                .setDefaultRealmName(VIRTUAL)
                .setPermissionMapper((permissionMappable, roles) -> LoginPermission.getInstance());
        final SecurityDomain virtualDomain = virtualDomainBuilder.build();

        httpAuthenticationFactory = HttpAuthenticationFactory.builder()
                .setFactory(virtualMechanismFactory)
                .setSecurityDomain(virtualDomain)
                .setMechanismConfigurationSelector(MechanismConfigurationSelector.constantSelector(MechanismConfiguration.EMPTY))
                .build();
    }

    @Override
    public void stop(StopContext context) {
        if (httpAuthenticationFactory != null) {
            httpAuthenticationFactory.shutdownAuthenticationMechanismFactory();
            httpAuthenticationFactory = null;
        }
    }

    @Override
    public HttpAuthenticationFactory getValue() throws IllegalStateException, IllegalArgumentException {
        return httpAuthenticationFactory;
    }

}

