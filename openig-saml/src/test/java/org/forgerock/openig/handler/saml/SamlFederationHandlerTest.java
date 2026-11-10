/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions Copyright [year] [name of copyright owner]".
 *
 * Copyright 2026 Wren Security.
 */

package org.forgerock.openig.handler.saml;

import static java.util.Collections.singleton;
import static java.util.Collections.singletonMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sun.identity.saml2.common.SAML2Constants;
import com.sun.identity.saml2.common.SAML2Exception;
import com.sun.identity.saml2.profile.SPACSUtils;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.http.session.Session;
import org.forgerock.http.session.SessionContext;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.mockito.MockedStatic;
import org.mockito.stubbing.OngoingStubbing;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

@SuppressWarnings("javadoc")
public class SamlFederationHandlerTest {

  private static final String ACS_URI = "http://ig.example.com/saml/fedletapplication";

  private SamlFederationHandler handler;
  private HttpServletRequest servletRequest;
  private HttpServletResponse servletResponse;
  private ServletOutputStream servletOutputStream;
  private Session session;

  @BeforeMethod
  public void setUp() throws Exception {
    handler =
        new SamlFederationHandler(
            singletonMap("username", "uid"),
            null,
            "|",
            null,
            null,
            "/home",
            null,
            "fedletapplication",
            "SPInitiatedSSO",
            "fedletSLORedirect",
            "fedletSloSoap",
            "SPInitiatedSLO");
    servletRequest = mock(HttpServletRequest.class);
    servletResponse = mock(HttpServletResponse.class);
    servletOutputStream = mock(ServletOutputStream.class);
    when(servletResponse.getOutputStream()).thenReturn(servletOutputStream);
    when(servletResponse.getCharacterEncoding()).thenReturn("UTF-8");
    session = new SimpleMapSession();
  }

  @Test
  public void shouldResetSessionBeforeStoringAssertionAttributes() throws Exception {
    session.put("username", "attacker");
    session.put("stale-attribute", "planted");
    when(servletRequest.getSession(false)).thenReturn(mock(HttpSession.class));

    try (MockedStatic<SPACSUtils> spacsUtils = mockStatic(SPACSUtils.class)) {
      stubProcessResponse(spacsUtils).thenReturn(validAssertion());

      assertThat(handleAssertion()).isEqualTo(Status.FOUND);
    }

    assertThat(session).containsOnlyKeys("username");
    assertThat(session.get("username")).asList().containsExactly("alice");
    verify(servletRequest).changeSessionId();
  }

  @Test
  public void shouldNotChangeSessionIdWithoutServletSession() throws Exception {
    session.put("stale-attribute", "planted");

    try (MockedStatic<SPACSUtils> spacsUtils = mockStatic(SPACSUtils.class)) {
      stubProcessResponse(spacsUtils).thenReturn(validAssertion());

      handleAssertion();
    }

    assertThat(session).containsOnlyKeys("username");
    verify(servletRequest, never()).changeSessionId();
  }

  @Test
  public void shouldKeepSessionWhenAssertionIsInvalid() throws Exception {
    session.put("username", "bob");
    when(servletRequest.getSession(false)).thenReturn(mock(HttpSession.class));

    try (MockedStatic<SPACSUtils> spacsUtils = mockStatic(SPACSUtils.class)) {
      stubProcessResponse(spacsUtils).thenThrow(new SAML2Exception("Invalid assertion"));

      assertThat(handleAssertion()).isEqualTo(Status.INTERNAL_SERVER_ERROR);
    }

    assertThat(session).containsOnlyKeys("username");
    assertThat(session.get("username")).isEqualTo("bob");
    verify(servletRequest, never()).changeSessionId();
  }

  private static OngoingStubbing<Map<?, ?>> stubProcessResponse(
      MockedStatic<SPACSUtils> spacsUtils) {
    return spacsUtils.when(
        () ->
            SPACSUtils.processResponseForFedlet(
                any(HttpServletRequest.class),
                any(HttpServletResponse.class),
                any(PrintWriter.class)));
  }

  private static Map<String, Object> validAssertion() {
    Map<String, Object> assertion = new HashMap<>();
    assertion.put(SAML2Constants.ATTRIBUTE_MAP, singletonMap("uid", singleton("alice")));
    return assertion;
  }

  private Status handleAssertion() throws Exception {
    try (Request request = new Request().setMethod("POST").setUri(ACS_URI);
        Response response = handler.handle(context(), request).get()) {
      return response.getStatus();
    }
  }

  private Context context() {
    AttributesContext attributesContext = new AttributesContext(new RootContext());
    attributesContext.getAttributes().put(HttpServletRequest.class.getName(), servletRequest);
    attributesContext.getAttributes().put(HttpServletResponse.class.getName(), servletResponse);
    return new SessionContext(attributesContext, session);
  }

  private static class SimpleMapSession extends HashMap<String, Object> implements Session {
    private static final long serialVersionUID = 1L;

    @Override
    public void save(Response response) throws IOException {}
  }
}
