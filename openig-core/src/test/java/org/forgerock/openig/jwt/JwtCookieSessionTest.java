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
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2014-2016 ForgeRock AS.
 * Portions Copyright 2026 Wren Security.
 */

package org.forgerock.openig.jwt;

import static java.util.Collections.singletonList;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;
import static org.forgerock.openig.jwt.JwtCookieSession.OPENIG_JWT_SESSION;
import static org.forgerock.openig.jwt.JwtSessionManager.DEFAULT_SESSION_TIMEOUT;
import static org.forgerock.openig.jwt.JwtSessionManager.MAX_SESSION_TIMEOUT;
import static org.forgerock.util.time.Duration.duration;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.concurrent.TimeUnit;

import org.forgerock.http.header.CookieHeader;
import org.forgerock.http.header.SetCookieHeader;
import org.forgerock.http.protocol.Cookie;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.builders.JwtBuilderFactory;
import org.forgerock.json.jose.jwe.EncryptedJwt;
import org.forgerock.json.jose.jwe.JweAlgorithm;
import org.forgerock.json.jose.jws.EncryptedThenSignedJwt;
import org.forgerock.json.jose.jws.handlers.HmacSigningHandler;
import org.forgerock.json.jose.jws.handlers.SigningHandler;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.util.encode.Base64url;
import org.forgerock.util.time.Duration;
import org.forgerock.util.time.TimeService;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

@SuppressWarnings("javadoc")
public class JwtCookieSessionTest {

    // @Checkstyle:off
    private static final BigInteger MODULUS = new BigInteger("25366522287061027145766827208458226830629591039641370484437237573482733225106980495329907410285723302359484019557948613507747774723701128512068985684077323164176142978871054978891228081911262380334592655484800696041293342250337107268538720062625968842947369102299463881897573053010426083360219898591908827384817839211514871012961744298396230437453764807628028579040290526455130578280054602043090696268994760427273443417446012796796868567107859046601993793261679739290641167736681316516030417256562248275149198563312970970756650273666899105644010406940086695646844468390081394359481011085005238347581853702391685885273");
    private static final BigInteger PRV_EXP = new BigInteger("1410337146703062661738985254754103239606734704833807524034792322022334088972390560749780278716276367288285547038532054571751162765300303447149722547360372709758866304213824352340432310350857718515406136814665647438858394736174463808379052462398238765452942248905254612198670702227852053668062335100695298682915926198743723963477953484561961416928118694212972336975821169100363124337920719319942872013440416946829272294033585130323069561009882570223911135171311912504622239037489351689487233124332993151783950958079669829448487948975403497155754259303918905603336514983266050316438665606746061050105864668839620692673");
    private static final BigInteger PUB_EXP = new BigInteger("65537");
    // @Checkstyle:on

    /**
     * Represents the following claims, encrypted with RSA1_5 (as issued before the switch to RSA-OAEP-256)
     * and then signed with 'HelloWorld' Hmac SHA-256.
     * {
     *     "a-value" : "ForgeRock OpenIG"
     * }
     */
    // @Checkstyle:off
    private static final String ORIGINAL = "eyJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
            + "ZXlKMGVYQWlPaUpLVjFRaUxDSmxibU1pT2lKQk1USTRRMEpETFVoVE1qVTJJaXdpWVd4bklqb2lVbE5CTVY4MUluMC5WT0hUQjUzNC1NOFRhbEI5V2I2c2ptc1FxUHlEMlFjdWVWa0ZHdl83QzBud0Y5WGpFQW9LQ0FfQXh3akdWVERVRnU5aFowYjRtbnJDV2EzTEhSdmNuekRzcWV5SVlBRDAtQ3pkbnN0ZWs4b3UzaEVVRF9zTHNnalF0OFduRjJOQlRHeUJBcjc2bGUzdloxVjhpZFFrajNPSkdic3FQQjQxWTAydlZHTGNjQm5FeGZ1bUd3bXNQb3pRTmdUNVZxcmptUGttN0Y1RVcyTFpPczVNdGFlU2NwQnlKX2lWNUdoY1ZIQmsya3VRMEwxS2RvNEhYY1RmVjNFbHRfTk11NGtobk9QbGN0YUJOR0FFS2EyeEtqa1hxdWJZVHlqYXZGamxzVjc5bEVtVEl2YXk0bnVuSXZIemRCTDBmSXQxbk1PZVVqOTZGNjVOMngyaEJmVnNGZGZDN3cuUjNQS1ZRaHJCdEJZcFdSbnp5VzBldy5hREsya2k1VXc5bjg0Um4yUHhCZnc0aEZONUZZWF95b3RuUDVSRWpkSDFzLml3cTVNY2RXR2VRZTQxdk9WNlBnalE."
            + "zL0oiiCuHbqRfRiH2Z5lrVdxXD3dcbj7VYRCEElRJ9M";
    // @Checkstyle:on

    /**
     * This claims represents a signed JWT token of the following payload.
     * {
     *     "a-value" : "ForgeRock OpenAM"
     * }
     * As we expect encrypted payload (instead of signed one), this value can be used as an invalid cookie value.
     */
    private static final String ALTERED = "eyAiYWxnIjogIkhTMjU2IiwgInR5cCI6ICJqd3QiIH0."
            + "eyAiYS12YWx1ZSI6ICJGb3JnZVJvY2sgT3BlbkFNIiB9."
            + "A8Z4xSPTfobTUYwwBaAymm1Ovfe1T3oMG5W9zFkOC-o";

    /**
     * Represents the following claims, only encrypted (OpenIG 4.0 and before).
     * {
     *     "a-value" : "ForgeRock OpenIG"
     * }
     */
    // @Checkstyle:off
    private static final String ONLY_ENCRYPTED = "eyAidHlwIjogIkpXVCIsICJhbGciOiAiUlNBRVNfUEtDUzFfVjFfNSIsICJlbmMiOiAiQTEyOENCQ19IUzI1NiIgfQ."
            + "VcBqC0hgiEdE2OqirUY9QGItTboPunTwlBaKOIQu81vwEYocaO20G0DecedPpiE99np5v1Rifw82kCfAd4Kvfg."
            + "InWrJbg39qUmMS11Hc54SA."
            + "xgatQtOnS-krnjq9hN_e3t4pPw_0yxJX1ByXOv0W0plRnAHoldtRFJLLOvS09TlC."
            + "14WSYyCegapzGCIU3fbGPw";
    // @Checkstyle:on

    private static final SigningHandler SIGNING_HANDLER =
            new HmacSigningHandler("HelloWorld".getBytes(StandardCharsets.UTF_8));

    /**
     * Static key pair used for test encryption/decryption.
     */
    private KeyPair keyPair;

    @BeforeMethod
    public void setUp() throws Exception {
        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(MODULUS, PUB_EXP);
        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(MODULUS, PRV_EXP);

        KeyFactory factory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = factory.generatePrivate(privateKeySpec);
        PublicKey publicKey = factory.generatePublic(publicKeySpec);

        keyPair = new KeyPair(publicKey, privateKey);
    }

    @Test(expectedExceptions = NullPointerException.class)
    public void shouldFailToSaveIfResponseIsNull() throws Exception {
        JwtCookieSession session = newJwtSession(new Request());
        session.clear(); // Set dirty on
        session.save(null);
    }

    @Test
    public void shouldStoreSessionContentInACookie() throws Exception {
        JwtCookieSession session = newJwtSession(new Request());
        session.put("a-value", "ForgeRock OpenIG");
        Response response = new Response(Status.OK);
        session.save(response);

        Cookie cookie = SetCookieHeader.valueOf(response).getCookies().get(0);

        JwtClaimsSet claimsSet = decryptClaimsSet(cookie.getValue());
        assertThat(claimsSet.get("a-value").asString()).isEqualTo("ForgeRock OpenIG");

        // The signed JWT's payload is the nested (encrypted) JWT
        String nestedJwe = new String(Base64url.decode(cookie.getValue().split("\\.")[1]), StandardCharsets.UTF_8);
        EncryptedJwt jwe = new JwtBuilderFactory().reconstruct(nestedJwe, EncryptedJwt.class);
        assertThat(jwe.getHeader().getAlgorithm()).isEqualTo(JweAlgorithm.RSA_OAEP_256);
    }

    @Test
    public void shouldExpireCookie() throws Exception {

        // Gives us control over the values returned by the TimeService to fake time passing quickly
        TimeService timeService = mock(TimeService.class);
        // The final now time is slightly higher then the session timeout to allow for the skew when checking if expired
        when(timeService.now()).thenReturn(0L, MILLISECONDS.convert(5L, MINUTES), MILLISECONDS.convert(35L, MINUTES));

        Duration sessionTimeout = duration("30 minutes");
        long expiredBy = sessionTimeout.to(MILLISECONDS);

        JwtCookieSession session = newJwtSession(new Request(), timeService, sessionTimeout);
        session.put("a-value", "ForgeRock OpenIG");
        Response response = new Response(Status.OK);
        session.save(response);

        Cookie jwtCookie = SetCookieHeader.valueOf(response).getCookies().get(0);
        // Expires date format does not include milliseconds so eliminate them.
        Long expectedTime = TimeUnit.SECONDS.toMillis(TimeUnit.MILLISECONDS.toSeconds(expiredBy));

        assertThat(jwtCookie.getExpires().getTime()).isEqualTo(expectedTime);

        Request request = new Request();
        setRequestCookie(request, jwtCookie.getValue());
        session = newJwtSession(request, timeService, sessionTimeout);
        response = new Response(Status.OK);
        // Unless we add another value, the session won't be seen as dirty and the JWT cookie won't be returned
        session.put("b-value", "ForgeRock OpenIG");
        session.save(response);
        jwtCookie = SetCookieHeader.valueOf(response).getCookies().get(0);

        // The initial session expiry time should be used since we already had a session so it should be the same
        assertThat(jwtCookie.getExpires().getTime()).isEqualTo(expectedTime);

        // The last timeService.now() call will be after expiry time, assert that the JWT cookie has now expired
        request = new Request();
        setRequestCookie(request, jwtCookie.getValue());
        session = newJwtSession(request, timeService, sessionTimeout);
        response = new Response(Status.OK);
        session.save(response);
        jwtCookie = SetCookieHeader.valueOf(response).getCookies().get(0);

        // With no session values we should be returned an expired cookie
        assertThat(jwtCookie.getExpires().getTime()).isEqualTo(0L);
    }

    @Test
    public void unlimitedSessionTimeout() throws Exception {

        TimeService timeService = mock(TimeService.class);
        when(timeService.now()).thenReturn(0L);

        JwtCookieSession session = newJwtSession(new Request(), timeService, Duration.UNLIMITED);
        session.put("a-value", "ForgeRock OpenIG");
        Response response = new Response(Status.OK);
        session.save(response);

        Cookie jwtCookie = SetCookieHeader.valueOf(response).getCookies().get(0);
        // Expires date format does not include milliseconds so eliminate them.
        Long expectedTime =
                TimeUnit.SECONDS.toMillis(TimeUnit.MILLISECONDS.toSeconds(MAX_SESSION_TIMEOUT.to(MILLISECONDS)));

        assertThat(jwtCookie.getExpires().getTime()).isEqualTo(expectedTime);
    }

    private JwtClaimsSet decryptClaimsSet(final String cookieValue) {
        JwtBuilderFactory factory = new JwtBuilderFactory();
        EncryptedThenSignedJwt jwt = factory.reconstruct(cookieValue, EncryptedThenSignedJwt.class);
        jwt.decrypt(keyPair.getPrivate());
        return jwt.getClaimsSet();
    }

    @Test
    public void shouldDetectModifiedContentWithSessionClear() throws Exception {
        Request request = new Request();
        setRequestCookie(request, ORIGINAL);
        JwtCookieSession session = newJwtSession(request);
        session.clear();
        Response response = new Response(Status.OK);
        session.save(response);
        Cookie jwtCookie = SetCookieHeader.valueOf(response).getCookies().get(0);

        // With no session values we should be returned an expired cookie
        assertThat(jwtCookie.getExpires().getTime()).isEqualTo(0L);
    }

    @Test
    public void shouldDetectModifiedContentWithSessionRemove() throws Exception {
        Request request = new Request();
        setRequestCookie(request, ORIGINAL);
        JwtCookieSession session = newJwtSession(request);
        session.remove("a-value");
        Response response = new Response(Status.OK);
        session.save(response);
        Cookie jwtCookie = SetCookieHeader.valueOf(response).getCookies().get(0);

        // With no session values we should be returned an expired cookie
        assertThat(jwtCookie.getExpires().getTime()).isEqualTo(0L);
    }

    @Test
    public void shouldNotStoreSessionContentInACookieWhenSessionWasNotModified() throws Exception {
        JwtCookieSession session = newJwtSession(new Request());
        Response response = new Response(Status.OK);
        session.save(response);

        assertThat(response.getHeaders().get("Set-Cookie")).isNull();
    }

    @Test
    public void shouldNotStoreSessionContentInACookieWhenSessionWasNotModifiedButOnlyInitialized() throws Exception {
        Request request = new Request();
        setRequestCookie(request, ORIGINAL);
        JwtCookieSession session = newJwtSession(request);
        Response response = new Response(Status.OK);
        session.save(response);

        // First time around with a non-empty pre-sessionTimeout JWT cookie, the expiry time will be added.
        Cookie jwtCookie = SetCookieHeader.valueOf(response).getCookies().get(0);
        assertThat(jwtCookie).isNotNull();

        request = new Request();
        setRequestCookie(request, jwtCookie.getValue());
        session = newJwtSession(request);
        response = new Response(Status.OK);
        session.save(response);

        // Since the session state has not changed, an updated JWT cookie should not be returned.
        assertThat(response.getHeaders().get("Set-Cookie")).isNull();
    }

    @Test
    public void shouldOverrideCookieName() throws Exception {
        JwtCookieSession session = newJwtSession(new Request(), "testCookieName", null);
        session.put("a-value", "ForgeRock OpenIG");
        Response response = new Response(Status.OK);
        session.save(response);

        Cookie cookie = SetCookieHeader.valueOf(response).getCookies().get(0);
        assertThat(cookie.getName()).isEqualTo("testCookieName");
        assertThat(cookie.getDomain()).isNull();
    }

    @Test
    public void shouldSetCookieDomain() throws Exception {
        JwtCookieSession session = newJwtSession(new Request(), "testCookieName", ".example.com");
        session.put("a-value", "ForgeRock OpenIG");
        Response response = new Response(Status.OK);
        session.save(response);

        Cookie cookie = SetCookieHeader.valueOf(response).getCookies().get(0);
        assertThat(cookie.getName()).isEqualTo("testCookieName");
        assertThat(cookie.getDomain()).isEqualTo(".example.com");
    }

    @DataProvider
    public static Object[][] invalidJwtSessionCookieValues() {
        // @Checkstyle:off
        return new Object[][] {
                { ALTERED },
                { ONLY_ENCRYPTED },
                { "Completely-invalid-JWT" }
        };
        // @Checkstyle:on
    }

    @Test(dataProvider = "invalidJwtSessionCookieValues")
    public void shouldNotLoadUnexpectedSession(String cookieValue) throws Exception {
        Request request = new Request();
        setRequestCookie(request, cookieValue);

        JwtCookieSession session = newJwtSession(request);
        assertThat(session).isEmpty();
    }

    @Test
    public void shouldLoadSignedAndEncryptedJwtSession() throws Exception {
        Request request = new Request();
        setRequestCookie(request, ORIGINAL);

        JwtCookieSession session = newJwtSession(request);
        assertThat(session).contains(entry("a-value", "ForgeRock OpenIG"));
    }

    @Test(expectedExceptions = IOException.class,
          expectedExceptionsMessageRegExp = "JWT session is too large.*")
    public void shouldFailIfSessionIsLargerThanFourThousandsKB() throws Exception {
        Request request = new Request();
        JwtCookieSession session = newJwtSession(request);
        session.put("more-than-4KB", generateMessageOf(5000));
        session.save(new Response(Status.OK));
    }

    @Test
    public void shouldWarnTheUserAboutGettingCloseToTheThreshold() throws Exception {
        Request request = new Request();
        JwtCookieSession session = new JwtCookieSession(
                request,
                keyPair,
                "Test",
                null,
                TimeService.SYSTEM,
                duration(DEFAULT_SESSION_TIMEOUT),
                SIGNING_HANDLER);
        session.put("in-between-3KB-and-4KB", generateMessageOf(1600));
        session.save(new Response(Status.OK));
    }

    private static Object generateMessageOf(final int size) {
        StringBuilder sb = new StringBuilder(size);
        for (int i = 0; i < size; i++) {
            sb.append("A");
        }
        return sb.toString();
    }

    private JwtCookieSession newJwtSession(final Request request) {
        return newJwtSession(request, TimeService.SYSTEM, duration(DEFAULT_SESSION_TIMEOUT));
    }

    private JwtCookieSession newJwtSession(final Request request,
                                           final TimeService timeService,
                                           final Duration sessionTimeout) {
        return new JwtCookieSession(request,
                                    keyPair,
                                    OPENIG_JWT_SESSION,
                                    null,
                                    timeService,
                                    sessionTimeout,
                                    SIGNING_HANDLER);
    }

    private JwtCookieSession newJwtSession(final Request request, String cookieName, String cookieDomain) {
        return new JwtCookieSession(request,
                                    keyPair,
                                    cookieName,
                                    cookieDomain,
                                    TimeService.SYSTEM,
                                    duration(DEFAULT_SESSION_TIMEOUT),
                                    SIGNING_HANDLER);
    }

    private static void setRequestCookie(final Request request, final String value) {
        request.getHeaders().add(
                new CookieHeader(singletonList(new Cookie().setValue(value).setName(OPENIG_JWT_SESSION))));
    }
}
