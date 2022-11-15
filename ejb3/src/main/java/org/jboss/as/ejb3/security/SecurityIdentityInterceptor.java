/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2022, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.jboss.as.ejb3.security;

import java.security.AccessController;
import java.security.PrivilegedAction;

import org.jboss.invocation.Interceptor;
import org.jboss.invocation.InterceptorContext;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.manager.WildFlySecurityManager;

/**
 * An {@code Interceptor} that will always runAs the current {@code SecurityIdentity}
 * to activate any outflow identities.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class SecurityIdentityInterceptor implements Interceptor {

    public static final SecurityIdentityInterceptor INSTANCE = new SecurityIdentityInterceptor();

    @Override
    public Object processInvocation(InterceptorContext context) throws Exception {
        final SecurityDomain securityDomain;
        if (WildFlySecurityManager.isChecking()) {
            securityDomain = AccessController.doPrivileged((PrivilegedAction<SecurityDomain>) SecurityDomain::getCurrent);
        } else {
            securityDomain = SecurityDomain.getCurrent();
        }
        if (securityDomain != null) {
            SecurityIdentity identity = securityDomain.getCurrentSecurityIdentity();
            return identity.runAsSupplierEx(() -> context.proceed());
        } else {
            return context.proceed();
        }
    }

}
