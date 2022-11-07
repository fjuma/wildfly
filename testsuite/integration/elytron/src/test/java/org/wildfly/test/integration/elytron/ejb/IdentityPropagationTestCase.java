/*
 * JBoss, Home of Professional Open Source.
 * Copyright (c) 2022, Red Hat, Inc., and individual contributors
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
package org.wildfly.test.integration.elytron.ejb;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.jboss.as.cli.Util.REMOVE;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OP;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OP_ADDR;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUBSYSTEM;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.WRITE_ATTRIBUTE_OPERATION;
import static org.jboss.as.controller.operations.common.Util.createAddOperation;
import static org.jboss.as.controller.operations.common.Util.getUndefineAttributeOperation;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.wildfly.test.integration.elytron.util.HttpUtil.get;

import java.io.File;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.OperateOnDeployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.as.arquillian.api.ServerSetupTask;
import org.jboss.as.arquillian.container.ManagementClient;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.client.ModelControllerClient;
import org.jboss.as.test.integration.management.base.AbstractMgmtTestBase;
import org.jboss.as.test.integration.management.util.ModelUtil;
import org.jboss.as.test.shared.ServerReload;
import org.jboss.as.test.shared.TestSuiteEnvironment;
import org.jboss.as.test.shared.integration.ejb.security.Util;
import org.jboss.dmr.ModelNode;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.EmptyAsset;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.EnterpriseArchive;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.test.integration.elytron.ejb.base.WhoAmIBean;
import org.wildfly.test.integration.elytron.ejb.propagation.local.ComplexServletLocal;
import org.wildfly.test.integration.elytron.ejb.propagation.local.EntryBeanLocal;
import org.wildfly.test.integration.elytron.ejb.propagation.local.EntryLocal;
import org.wildfly.test.integration.elytron.ejb.propagation.local.ManagementBeanLocal;
import org.wildfly.test.integration.elytron.ejb.propagation.local.SimpleServletLocal;
import org.wildfly.test.integration.elytron.ejb.propagation.local.WhoAmIBeanLocal;
import org.wildfly.test.integration.elytron.ejb.propagation.local.WhoAmILocal;
import org.wildfly.test.integration.elytron.ejb.propagation.remote.ComplexServletRemote;
import org.wildfly.test.integration.elytron.ejb.propagation.remote.EntryBeanRemote;
import org.wildfly.test.integration.elytron.ejb.propagation.remote.EntryRemote;
import org.wildfly.test.integration.elytron.ejb.propagation.remote.ManagementBeanRemote;
import org.wildfly.test.integration.elytron.ejb.propagation.remote.ServletOnlyRemote;
import org.wildfly.test.integration.elytron.ejb.propagation.remote.SimpleServletRemote;
import org.wildfly.test.integration.elytron.ejb.propagation.remote.WhoAmIBeanRemote;
import org.wildfly.test.integration.elytron.ejb.propagation.remote.WhoAmIRemote;
import org.wildfly.test.integration.elytron.util.HttpUtil;
import org.wildfly.test.security.common.elytron.EjbElytronDomainSetup;
import org.wildfly.test.security.common.elytron.ElytronDomainSetup;
import org.wildfly.test.security.common.elytron.ServletElytronDomainSetup;

/**
 * Test class to hold the identity propagation scenarios involving different security domains.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 *
 * NOTE: References in this file to Enterprise JavaBeans(EJB) refer to the Jakarta Enterprise Beans unless otherwise noted.
 */
@RunWith(Arquillian.class)
@ServerSetup({ IdentityPropagationTestCase.ServletDomainSetupOverride.class, IdentityPropagationTestCase.EJBDomainSetupOverride.class, IdentityPropagationTestCase.PropagationSetup.class, ServletElytronDomainSetup.class})
public class IdentityPropagationTestCase {

    private static final String SERVLET_SECURITY_DOMAIN_NAME = "elytron-tests";
    private static final String EJB_SECURITY_DOMAIN_NAME = "ejb-domain";
    private static final String SINGLE_DEPLOYMENT_LOCAL = "single-deployment-local";
    private static final String EAR_DEPLOYMENT_WITH_EJB_LOCAL = "ear-ejb-deployment-local";
    private static final String EAR_DEPLOYMENT_WITH_SERVLET_AND_EJB_LOCAL = "ear-servlet-ejb-deployment-local";
    private static final String SINGLE_DEPLOYMENT_REMOTE = "single-deployment-remote";
    private static final String EAR_DEPLOYMENT_WITH_EJB_REMOTE = "ear-ejb-deployment-remote";
    private static final String EAR_DEPLOYMENT_WITH_SERVLET_AND_EJB_REMOTE = "ear-servlet-ejb-deployment-remote";
    private static final String EAR_DEPLOYMENT_WITH_SERVLET = "ear-servlet";

    @ArquillianResource
    private URL url;

    @Deployment(name= EAR_DEPLOYMENT_WITH_EJB_LOCAL, order = 1)
    public static Archive<?> ejbDeploymentLocal() {
        final String SERVER_HOST_PORT = TestSuiteEnvironment.getHttpAddress() + ":" + TestSuiteEnvironment.getHttpPort();
        final Package currentPackage = IdentityPropagationTestCase.class.getPackage();
        final JavaArchive jar = ShrinkWrap.create(JavaArchive.class, EAR_DEPLOYMENT_WITH_EJB_LOCAL + "-ejb.jar")
                .addClass(WhoAmIBeanLocal.class).addClass(EntryBeanLocal.class)
                .addClass(WhoAmILocal.class).addClass(EntryLocal.class)
                .addClass(WhoAmIBean.class)
                .addAsManifestResource(EmptyAsset.INSTANCE, "beans.xml")
                .addAsManifestResource(currentPackage, "jboss-ejb3.xml", "jboss-ejb3.xml");
        final EnterpriseArchive ear = ShrinkWrap.create(EnterpriseArchive.class, EAR_DEPLOYMENT_WITH_EJB_LOCAL + ".ear");
        ear.addAsModule(jar);
        return ear;
    }

    @Deployment(name= EAR_DEPLOYMENT_WITH_EJB_REMOTE, order = 2)
    public static Archive<?> ejbDeploymentRemote() {
        final String SERVER_HOST_PORT = TestSuiteEnvironment.getHttpAddress() + ":" + TestSuiteEnvironment.getHttpPort();
        final Package currentPackage = IdentityPropagationTestCase.class.getPackage();
        final JavaArchive jar = ShrinkWrap.create(JavaArchive.class, EAR_DEPLOYMENT_WITH_EJB_REMOTE + "-ejb.jar")
                .addClass(WhoAmIBeanRemote.class).addClass(EntryBeanRemote.class)
                .addClass(WhoAmIRemote.class).addClass(EntryRemote.class)
                .addClass(WhoAmIBean.class)
                .addAsManifestResource(EmptyAsset.INSTANCE, "beans.xml")
                .addAsManifestResource(currentPackage, "jboss-ejb3.xml", "jboss-ejb3.xml");
        final EnterpriseArchive ear = ShrinkWrap.create(EnterpriseArchive.class, EAR_DEPLOYMENT_WITH_EJB_REMOTE + ".ear");
        ear.addAsModule(jar);
        return ear;
    }

    @Deployment(name= SINGLE_DEPLOYMENT_LOCAL, order = 3)
    public static Archive<?> singleDeploymentLocal() {
        final String SERVER_HOST_PORT = TestSuiteEnvironment.getHttpAddress() + ":" + TestSuiteEnvironment.getHttpPort();
        final Package currentPackage = IdentityPropagationTestCase.class.getPackage();
        final WebArchive war = ShrinkWrap.create(WebArchive.class, SINGLE_DEPLOYMENT_LOCAL + "-web.war")
                .addClass(HttpUtil.class)
                .addClasses(SimpleServletLocal.class, IdentityPropagationTestCase.class)
                .addClasses(ServletDomainSetupOverride.class, EJBDomainSetupOverride.class, PropagationSetup.class,
                        PropagationSetup.class, ServletElytronDomainSetup.class,
                        ElytronDomainSetup.class, AbstractMgmtTestBase.class, EjbElytronDomainSetup.class)
                .addAsWebInfResource(currentPackage, "web.xml", "web.xml")
                .addAsWebInfResource(currentPackage, "jboss-web.xml", "jboss-web.xml");
        final JavaArchive jar = ShrinkWrap.create(JavaArchive.class, SINGLE_DEPLOYMENT_LOCAL + "-ejb.jar")
                .addClass(WhoAmIBeanLocal.class).addClass(EntryBeanLocal.class)
                .addClass(WhoAmILocal.class).addClass(EntryLocal.class)
                .addClass(WhoAmIBean.class)
                .addAsManifestResource(EmptyAsset.INSTANCE, "beans.xml")
                .addAsManifestResource(currentPackage, "jboss-ejb3.xml", "jboss-ejb3.xml");
        final EnterpriseArchive ear = ShrinkWrap.create(EnterpriseArchive.class, SINGLE_DEPLOYMENT_LOCAL + ".ear");
        ear.addAsModule(war);
        ear.addAsModule(jar);
        return ear;
    }

    @Deployment(name= EAR_DEPLOYMENT_WITH_SERVLET_AND_EJB_LOCAL, order = 4)
    public static Archive<?> servletAndEJBDeploymentLocal() {
        final String SERVER_HOST_PORT = TestSuiteEnvironment.getHttpAddress() + ":" + TestSuiteEnvironment.getHttpPort();
        final Package currentPackage = IdentityPropagationTestCase.class.getPackage();
        final WebArchive war = ShrinkWrap.create(WebArchive.class, EAR_DEPLOYMENT_WITH_SERVLET_AND_EJB_LOCAL + "-web.war")
                .addClass(HttpUtil.class)
                .addClasses(ComplexServletLocal.class, IdentityPropagationTestCase.class)
                .addClasses(ServletDomainSetupOverride.class, EJBDomainSetupOverride.class, PropagationSetup.class,
                        PropagationSetup.class, ServletElytronDomainSetup.class,
                        ElytronDomainSetup.class, AbstractMgmtTestBase.class, EjbElytronDomainSetup.class)
                .addAsWebInfResource(currentPackage, "web.xml", "web.xml")
                .addAsWebInfResource(currentPackage, "jboss-web.xml", "jboss-web.xml");
        final JavaArchive jar = ShrinkWrap.create(JavaArchive.class, EAR_DEPLOYMENT_WITH_SERVLET_AND_EJB_LOCAL + "-ejb.jar")
                .addClass(ManagementBeanLocal.class)
                .addAsManifestResource(EmptyAsset.INSTANCE, "beans.xml")
                .addAsManifestResource(currentPackage, "jboss-ejb3.xml", "jboss-ejb3.xml")
                .addAsManifestResource(new StringAsset("Dependencies: deployment." + EAR_DEPLOYMENT_WITH_EJB_LOCAL + ".ear" + "." + EAR_DEPLOYMENT_WITH_EJB_LOCAL + "-ejb.jar"), "MANIFEST.MF");
        final EnterpriseArchive ear = ShrinkWrap.create(EnterpriseArchive.class, EAR_DEPLOYMENT_WITH_SERVLET_AND_EJB_LOCAL + ".ear");
        ear.addAsModule(war);
        ear.addAsModule(jar);
        return ear;
    }

    @Deployment(name= EAR_DEPLOYMENT_WITH_SERVLET, order = 5)
    public static Archive<?> servletOnly() {
        final String SERVER_HOST_PORT = TestSuiteEnvironment.getHttpAddress() + ":" + TestSuiteEnvironment.getHttpPort();
        final Package currentPackage = IdentityPropagationTestCase.class.getPackage();
        final WebArchive war = ShrinkWrap.create(WebArchive.class, EAR_DEPLOYMENT_WITH_SERVLET + "-web.war")
                .addClass(HttpUtil.class)
                .addClasses(ServletOnlyRemote.class, IdentityPropagationTestCase.class)
                .addClasses(ServletDomainSetupOverride.class, EJBDomainSetupOverride.class, PropagationSetup.class,
                        PropagationSetup.class, ServletElytronDomainSetup.class,
                        ElytronDomainSetup.class, AbstractMgmtTestBase.class, EjbElytronDomainSetup.class)
                .addAsWebInfResource(currentPackage, "web.xml", "web.xml")
                .addAsWebInfResource(currentPackage, "jboss-web.xml", "jboss-web.xml");
        final JavaArchive jar = ShrinkWrap.create(JavaArchive.class, EAR_DEPLOYMENT_WITH_SERVLET + "-ejb.jar")
                .addAsManifestResource(EmptyAsset.INSTANCE, "beans.xml")
                .addAsManifestResource(currentPackage, "jboss-ejb3.xml", "jboss-ejb3.xml")
                .addAsManifestResource(new StringAsset("Dependencies: deployment." + EAR_DEPLOYMENT_WITH_EJB_REMOTE + ".ear" + "." + EAR_DEPLOYMENT_WITH_EJB_REMOTE + "-ejb.jar"), "MANIFEST.MF");
        final EnterpriseArchive ear = ShrinkWrap.create(EnterpriseArchive.class, EAR_DEPLOYMENT_WITH_SERVLET + ".ear");
        ear.addAsModule(war);
        ear.addAsModule(jar);
        return ear;
    }

    @Deployment(name= SINGLE_DEPLOYMENT_REMOTE, order = 6)
    public static Archive<?> singleDeploymentRemote() {
        final String SERVER_HOST_PORT = TestSuiteEnvironment.getHttpAddress() + ":" + TestSuiteEnvironment.getHttpPort();
        final Package currentPackage = IdentityPropagationTestCase.class.getPackage();
        final WebArchive war = ShrinkWrap.create(WebArchive.class, SINGLE_DEPLOYMENT_REMOTE + "-web.war")
                .addClass(HttpUtil.class)
                .addClasses(SimpleServletRemote.class, IdentityPropagationTestCase.class)
                .addClass(Util.class)
                .addClasses(ServletDomainSetupOverride.class, EJBDomainSetupOverride.class, PropagationSetup.class,
                        PropagationSetup.class, ServletElytronDomainSetup.class,
                        ElytronDomainSetup.class, AbstractMgmtTestBase.class, EjbElytronDomainSetup.class)
                .addAsWebInfResource(currentPackage, "web.xml", "web.xml")
                .addAsWebInfResource(currentPackage, "jboss-web.xml", "jboss-web.xml");
        final JavaArchive jar = ShrinkWrap.create(JavaArchive.class, SINGLE_DEPLOYMENT_REMOTE + "-ejb.jar")
                .addClass(WhoAmIBeanRemote.class).addClass(EntryBeanRemote.class)
                .addClass(WhoAmIRemote.class).addClass(EntryRemote.class)
                .addClass(WhoAmIBean.class)
                .addAsManifestResource(EmptyAsset.INSTANCE, "beans.xml")
                .addAsManifestResource(currentPackage, "jboss-ejb3.xml", "jboss-ejb3.xml");
        final EnterpriseArchive ear = ShrinkWrap.create(EnterpriseArchive.class, SINGLE_DEPLOYMENT_REMOTE + ".ear");
        ear.addAsModule(war);
        ear.addAsModule(jar);
        return ear;
    }

    @Deployment(name= EAR_DEPLOYMENT_WITH_SERVLET_AND_EJB_REMOTE, order = 7)
    public static Archive<?> servletAndEJBDeploymentRemote() {
        final String SERVER_HOST_PORT = TestSuiteEnvironment.getHttpAddress() + ":" + TestSuiteEnvironment.getHttpPort();
        final Package currentPackage = IdentityPropagationTestCase.class.getPackage();
        final WebArchive war = ShrinkWrap.create(WebArchive.class, EAR_DEPLOYMENT_WITH_SERVLET_AND_EJB_REMOTE + "-web.war")
                .addClass(HttpUtil.class)
                .addClasses(ComplexServletRemote.class, IdentityPropagationTestCase.class)
                .addClasses(ServletDomainSetupOverride.class, EJBDomainSetupOverride.class, PropagationSetup.class,
                        PropagationSetup.class, ServletElytronDomainSetup.class,
                        ElytronDomainSetup.class, AbstractMgmtTestBase.class, EjbElytronDomainSetup.class)
                .addAsWebInfResource(currentPackage, "web.xml", "web.xml")
                .addAsWebInfResource(currentPackage, "jboss-web.xml", "jboss-web.xml");
        final JavaArchive jar = ShrinkWrap.create(JavaArchive.class, EAR_DEPLOYMENT_WITH_SERVLET_AND_EJB_REMOTE + "-ejb.jar")
                .addClass(ManagementBeanRemote.class)
                .addClass(Util.class)
                .addAsManifestResource(EmptyAsset.INSTANCE, "beans.xml")
                .addAsManifestResource(currentPackage, "jboss-ejb3.xml", "jboss-ejb3.xml")
                .addAsManifestResource(new StringAsset("Dependencies: deployment." + EAR_DEPLOYMENT_WITH_EJB_REMOTE + ".ear" + "." + EAR_DEPLOYMENT_WITH_EJB_REMOTE + "-ejb.jar"), "MANIFEST.MF");
        final EnterpriseArchive ear = ShrinkWrap.create(EnterpriseArchive.class, EAR_DEPLOYMENT_WITH_SERVLET_AND_EJB_REMOTE + ".ear");
        ear.addAsModule(war);
        ear.addAsModule(jar);
        return ear;
    }

    /**
     * Servlet -> EJB propagation scenarios involving different security domains within a single deployment.
     */

    @Test
    @OperateOnDeployment(SINGLE_DEPLOYMENT_LOCAL)
    public void testServletToEjbSingleDeploymentLocal() throws Exception {
        testServletToEjbInvocation();
    }

    @Test
    @OperateOnDeployment(SINGLE_DEPLOYMENT_REMOTE)
    public void testServletToEjbSingleDeploymentRemote() throws Exception {
        testServletToEjbInvocation();
    }

    private void testServletToEjbInvocation() throws Exception {
        String result = getWhoAmI("?method=whoAmI");
        assertEquals("user1", result);
        result = getWhoAmI("?method=doIHaveRole&role=Managers");
        assertEquals("true", result);
    }

    @Test
    @OperateOnDeployment(SINGLE_DEPLOYMENT_REMOTE)
    public void testWrongPasswordSingleDeployment() throws Exception {
        testWrongPassword();
    }

    @Test
    @OperateOnDeployment(SINGLE_DEPLOYMENT_REMOTE)
    public void testServletToEjbSingleDeploymentProgrammaticAuth() throws Exception {
        String result = getWhoAmI("?method=switchWhoAmI&username=user2&password=password2&role=Managers2");
        assertEquals("user2,true", result);
    }

    private void testWrongPassword() throws Exception {
        try {
            getWhoAmIWrongPassword("?method=whoAmI");
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("Unauthorized"));
        }
    }

    /**
     * Servlet -> EJB -> EJB propagation scenarios involving different security domains across deployments.
     */

    @Test
    @OperateOnDeployment(EAR_DEPLOYMENT_WITH_SERVLET_AND_EJB_LOCAL)
    public void testEarToEarLocal() throws Exception {
        testServletToEjbToEjbInvocation();
    }

    @Test
    @OperateOnDeployment(EAR_DEPLOYMENT_WITH_SERVLET_AND_EJB_REMOTE)
    public void testEarToEarRemote() throws Exception {
        testServletToEjbToEjbInvocation();
    }

    private void testServletToEjbToEjbInvocation() throws Exception {
        String result = getWhoAmI("?method=whoAmI");
        assertEquals("user1", result);
        result = getWhoAmI("?method=invokeEntryDoIHaveRole&role=Managers");
        assertEquals("true", result);
    }

    @Test
    @OperateOnDeployment(EAR_DEPLOYMENT_WITH_SERVLET_AND_EJB_REMOTE)
    public void testWrongPasswordEarToEar() throws Exception {
        testWrongPassword();
    }

    @Test
    @OperateOnDeployment(EAR_DEPLOYMENT_WITH_SERVLET)
    public void testServletToEjbEarToEar() throws Exception {
        testServletToEjbInvocation();
    }

    @Test
    @OperateOnDeployment(EAR_DEPLOYMENT_WITH_SERVLET_AND_EJB_REMOTE)
    public void testEarToEarProgrammaticAuth() throws Exception {
        String result = getWhoAmI("?method=switchThenInvokeEntryDoIHaveRole&username=user2&password=password2&role=Managers2");
        assertEquals("user2,true", result);
    }

    private String getWhoAmI(String queryString) throws Exception {
        return get(url + "whoAmI" + queryString, "user1", "password1", 10, SECONDS);
    }

    private String getWhoAmIWrongPassword(String queryString) throws Exception {
        return get(url + "whoAmI" + queryString, "user1", "wrongpassword", 10, SECONDS);
    }

    static class ServletDomainSetupOverride extends ElytronDomainSetup {
        public ServletDomainSetupOverride() {
            super(new File(IdentityPropagationTestCase.class.getResource("users.properties").getFile()).getAbsolutePath(),
                    new File(IdentityPropagationTestCase.class.getResource("roles.properties").getFile()).getAbsolutePath(),
                    SERVLET_SECURITY_DOMAIN_NAME);
        }
    }

    static class EJBDomainSetupOverride extends ElytronDomainSetup {
        public EJBDomainSetupOverride() {
            super(new File(IdentityPropagationTestCase.class.getResource("ejbusers.properties").getFile()).getAbsolutePath(),
                    new File(IdentityPropagationTestCase.class.getResource("ejbroles.properties").getFile()).getAbsolutePath(),
                    EJB_SECURITY_DOMAIN_NAME);
        }
    }

    static class PropagationSetup extends AbstractMgmtTestBase implements ServerSetupTask {
        private ManagementClient managementClient;

        @Override
        public void setup(ManagementClient managementClient, String containerId) throws Exception {
            this.managementClient = managementClient;
            final List<ModelNode> updates = new ArrayList<ModelNode>();

            updates.add(getAddEjbApplicationSecurityDomainOp(EJB_SECURITY_DOMAIN_NAME, EJB_SECURITY_DOMAIN_NAME));
            updates.add(getAddEjbApplicationSecurityDomainOp(SERVLET_SECURITY_DOMAIN_NAME, SERVLET_SECURITY_DOMAIN_NAME));

            // /subsystem=elytron/security-domain=elytron-tests:write-attribute(name=outflow-security-domains, value=["ejb-domain"])
            ModelNode op = new ModelNode();
            op.get(OP).set(WRITE_ATTRIBUTE_OPERATION);
            op.get(OP_ADDR).add(SUBSYSTEM, "elytron");
            op.get(OP_ADDR).add("security-domain", SERVLET_SECURITY_DOMAIN_NAME);
            op.get("name").set("outflow-security-domains");
            ModelNode outflowDomains = new ModelNode();
            outflowDomains.add(EJB_SECURITY_DOMAIN_NAME);
            op.get("value").set(outflowDomains);
            updates.add(op);

            // /subsystem=elytron/security-domain=ejb-domain:write-attribute(name=trusted-security-domains, value=["elytron-tests"])
            op = new ModelNode();
            op.get(OP).set(WRITE_ATTRIBUTE_OPERATION);
            op.get(OP_ADDR).add(SUBSYSTEM, "elytron");
            op.get(OP_ADDR).add("security-domain", EJB_SECURITY_DOMAIN_NAME);
            op.get("name").set("trusted-security-domains");
            ModelNode trustedDomains = new ModelNode();
            trustedDomains.add(SERVLET_SECURITY_DOMAIN_NAME);
            op.get("value").set(trustedDomains);
            updates.add(op);

            executeOperations(updates);

            ServerReload.executeReloadAndWaitForCompletion(managementClient, 50000);
        }

        @Override
        public void tearDown(final ManagementClient managementClient, final String containerId) throws Exception {
            final List<ModelNode> updates = new ArrayList<>();

            updates.add(getUndefineAttributeOperation(PathAddress.pathAddress("subsystem", "elytron").append("security-domain", SERVLET_SECURITY_DOMAIN_NAME), "outflow-security-domains"));
            updates.add(getUndefineAttributeOperation(PathAddress.pathAddress("subsystem", "elytron").append("security-domain", EJB_SECURITY_DOMAIN_NAME), "trusted-security-domains"));

            ModelNode op = ModelUtil.createOpNode(
                    "subsystem=ejb3/application-security-domain=" + EJB_SECURITY_DOMAIN_NAME, REMOVE);
            updates.add(op);

            op = ModelUtil.createOpNode(
                    "subsystem=ejb3/application-security-domain=" + SERVLET_SECURITY_DOMAIN_NAME, REMOVE);
            updates.add(op);
            executeOperations(updates);
        }

        @Override
        protected ModelControllerClient getModelControllerClient() {
            return managementClient.getControllerClient();
        }

        private static PathAddress getEjbApplicationSecurityDomainAddress(String ejbDomainName) {
            return PathAddress.pathAddress()
                    .append(SUBSYSTEM, "ejb3")
                    .append("application-security-domain", ejbDomainName);
        }

        private static ModelNode getAddEjbApplicationSecurityDomainOp(String ejbDomainName, String securityDomainName) {
            ModelNode op = createAddOperation(getEjbApplicationSecurityDomainAddress(ejbDomainName));
            op.get("security-domain").set(securityDomainName);
            return op;
        }
    }


}
