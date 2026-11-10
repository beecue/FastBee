package com.fastbee.security;

import com.alibaba.fastjson2.JSONObject;
import com.fastbee.common.constant.CacheConstants;
import com.fastbee.common.constant.Constants;
import com.fastbee.common.core.domain.entity.SysUser;
import com.fastbee.common.core.domain.model.LoginUser;
import com.fastbee.common.core.domain.model.MqttClientPrincipal;
import com.fastbee.common.core.redis.RedisCache;
import com.fastbee.data.controller.ToolController;
import com.fastbee.iot.model.MqttAuthenticationModel;
import com.fastbee.iot.service.IToolService;
import com.fastbee.iot.service.impl.ToolServiceImpl;
import com.fastbee.mqtt.auth.AuthService;
import com.fastbee.mqttclient.MqttClientConfig;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class MqttCallbackSecurityTest {
    private static final String USERNAME = "test-server";
    private static final String SERVER_PASSWORD = "test-only-server-password-0123456789";
    private static final String CALLBACK_TOKEN = "test-only-callback-token-0123456789";
    private static final String SERVER_ID = "server-test";
    private static final String DEVICE_ID = "S&test-device&12&34";

    @Test
    public void embeddedDefaultsGenerateDifferentPasswordsAndDisableCallbacks() throws Exception {
        try (AnnotationConfigApplicationContext first = newContext();
             AnnotationConfigApplicationContext second = newContext()) {
            MqttClientConfig config = first.getBean(MqttClientConfig.class);
            assertEquals("tcp://127.0.0.1:11883", config.getHostUrl());
            assertTrue(config.getPassword().length() >= 32);
            assertNotEquals(config.getPassword(), second.getBean(MqttClientConfig.class).getPassword());
            assertFalse(config.toString().contains(config.getPassword()));

            ToolController controller = controller(config, mock(IToolService.class));
            assertLegacyDenied(controller.mqttAuth(null, SERVER_ID, config.getUsername(), config.getPassword(), null));
            assertV5Result(controller.mqttAuthv5("", request(SERVER_ID, config.getUsername(), config.getPassword())), "deny");
        }
    }

    @Test
    public void rejectsDefaultPasswordAndWeakOrReusedCallbackTokensAtStartup() {
        assertThrows(IllegalStateException.class, () -> config("fastbee", ""));
        assertThrows(IllegalStateException.class, () -> config(SERVER_PASSWORD, "weak"));
        assertThrows(IllegalStateException.class, () -> config(SERVER_PASSWORD, SERVER_PASSWORD));
    }

    @Test
    public void embeddedBrokerRejectsPublicDefaultsAndAcceptsItsOwnPublisher() throws Exception {
        MqttClientConfig config = config("", "");
        IToolService tool = mock(IToolService.class);
        when(tool.returnUnauthorized(any(MqttAuthenticationModel.class), anyString()))
                .thenReturn(ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized"));
        when(tool.clientAuth(DEVICE_ID, "device-user", "device-password", "192.0.2.1")).thenReturn(ResponseEntity.ok("ok"));
        AuthService service = new AuthService();
        inject(service, "mqttConfig", config);
        inject(service, "toolService", tool);

        assertNull(service.authenticate(SERVER_ID, "fastbee", "fastbee"));
        assertEquals(MqttClientPrincipal.ClientType.SERVER,
                service.authenticate(SERVER_ID, config.getUsername(), config.getPassword()).getClientType());
        assertEquals(MqttClientPrincipal.ClientType.DEVICE,
                service.authenticate(DEVICE_ID, "device-user", "device-password", "192.0.2.1").getClientType());
    }

    @Test
    public void bothCallbacksRequireBrokerTokenEvenWithCorrectClientCredentials() throws Exception {
        IToolService tool = mock(IToolService.class);
        ToolController controller = controller(config(SERVER_PASSWORD, CALLBACK_TOKEN), tool);
        for (String token : new String[]{null, "invalid-token", SERVER_PASSWORD}) {
            assertLegacyDenied(controller.mqttAuth(token, SERVER_ID, USERNAME, SERVER_PASSWORD, null));
            assertV5Result(controller.mqttAuthv5(token, request(SERVER_ID, USERNAME, SERVER_PASSWORD)), "deny");
            assertLegacyDenied(controller.mqttAuth(token, DEVICE_ID, "device-user", "device-password", null));
            assertV5Result(controller.mqttAuthv5(token, request(DEVICE_ID, "device-user", "device-password")), "deny");
        }
        verifyNoInteractions(tool);
    }

    @Test
    public void trustedCallbackStillChecksServerCredentialsAndPreservesProtocolResponses() throws Exception {
        MqttClientConfig config = config(SERVER_PASSWORD, CALLBACK_TOKEN);
        assertFalse(config.toString().contains(CALLBACK_TOKEN));
        ToolController controller = controller(config, new ToolServiceImpl());

        assertLegacyDenied(controller.mqttAuth(CALLBACK_TOKEN, SERVER_ID, "fastbee", "fastbee", null));
        assertV5Result(controller.mqttAuthv5(CALLBACK_TOKEN, request(SERVER_ID, "fastbee", "fastbee")), "deny");
        assertV5Result(controller.mqttAuthv5(CALLBACK_TOKEN, request(SERVER_ID, USERNAME, CALLBACK_TOKEN)), "deny");
        ResponseEntity<?> legacy = controller.mqttAuth(CALLBACK_TOKEN, SERVER_ID, USERNAME, SERVER_PASSWORD, null);
        assertEquals(HttpStatus.OK, legacy.getStatusCode());
        assertEquals("ok", legacy.getBody());
        assertV5Result(controller.mqttAuthv5(CALLBACK_TOKEN, request(SERVER_ID, USERNAME, SERVER_PASSWORD)), "allow");
        assertLegacyDenied(controller.mqttAuth(CALLBACK_TOKEN, SERVER_ID, USERNAME, null, null));
        assertV5Result(controller.mqttAuthv5(CALLBACK_TOKEN, new JSONObject()), "deny");
        assertV5Result(controller.mqttAuthv5(CALLBACK_TOKEN, null), "deny");
    }

    @Test
    public void trustedCallbackPreservesDeviceAuthenticationAndV5Denials() throws Exception {
        IToolService tool = mock(IToolService.class);
        ToolController controller = controller(config(SERVER_PASSWORD, CALLBACK_TOKEN), tool);
        String peer = "192.0.2.1";
        when(tool.clientAuth(DEVICE_ID, "device-user", "device-password", peer)).thenReturn(ResponseEntity.ok("ok"));
        JSONObject allow = new JSONObject();
        allow.put("result", "allow");
        allow.put("is_superuser", false);
        when(tool.clientAuthv5(DEVICE_ID, "device-user", "device-password", peer)).thenReturn(ResponseEntity.ok(allow));
        when(tool.clientAuthv5(DEVICE_ID, "device-user", "bad-password", null))
                .thenReturn(ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized"));

        assertEquals("ok", controller.mqttAuth(CALLBACK_TOKEN, DEVICE_ID, "device-user", "device-password", peer).getBody());
        JSONObject deviceRequest = request(DEVICE_ID, "device-user", "device-password");
        deviceRequest.put("peerhost", peer);
        assertV5Result(controller.mqttAuthv5(CALLBACK_TOKEN, deviceRequest), "allow");
        assertV5Result(controller.mqttAuthv5(CALLBACK_TOKEN, request(DEVICE_ID, "device-user", "bad-password")), "deny");
    }

    @Test
    public void deviceAuthenticationErrorsAreDeniedInBothProtocolVersions() throws Exception {
        IToolService tool = mock(IToolService.class);
        String invalidDeviceId = "S&test-device&not-a-product&34";
        when(tool.clientAuth(invalidDeviceId, "device-user", "device-password", null)).thenThrow(NumberFormatException.class);
        when(tool.clientAuthv5(invalidDeviceId, "device-user", "device-password", null)).thenThrow(NumberFormatException.class);
        ToolController controller = controller(config(SERVER_PASSWORD, CALLBACK_TOKEN), tool);

        assertLegacyDenied(controller.mqttAuth(CALLBACK_TOKEN, invalidDeviceId, "device-user", "device-password", null));
        assertV5Result(controller.mqttAuthv5(CALLBACK_TOKEN, request(invalidDeviceId, "device-user", "device-password")), "deny");
    }

    @Test
    public void trustedCallbackPreservesWebAndPhoneSessionChecks() throws Exception {
        RedisCache redis = mock(RedisCache.class);
        ToolController controller = controller(config(SERVER_PASSWORD, CALLBACK_TOKEN), new ToolServiceImpl());
        String signingKey = "local-mqtt-callback-regression-signing-key";
        inject(controller, "secret", signingKey);
        inject(controller, "redisCache", redis);
        String session = "mqtt-callback-test-session";
        String jwt = Jwts.builder().claim(Constants.LOGIN_USER_KEY, session)
                .signWith(SignatureAlgorithm.HS512, signingKey).compact();
        SysUser user = new SysUser();
        user.setStatus("0");
        user.setDelFlag("0");
        LoginUser login = new LoginUser(42L, 1L, user, Collections.emptySet());
        when(redis.getCacheObject(CacheConstants.LOGIN_TOKEN_KEY + session)).thenReturn(login);

        assertEquals("ok", controller.mqttAuth(CALLBACK_TOKEN, "web-test", "web-user", jwt, null).getBody());
        assertV5Result(controller.mqttAuthv5(CALLBACK_TOKEN, request("phone-test", "web-user", jwt)), "allow");
        when(redis.getCacheObject(CacheConstants.LOGIN_TOKEN_KEY + session)).thenReturn(null);
        assertLegacyDenied(controller.mqttAuth(CALLBACK_TOKEN, "web-test", "web-user", jwt, null));
        assertV5Result(controller.mqttAuthv5(CALLBACK_TOKEN, request("phone-test", "web-user", jwt)), "deny");
    }

    private static AnnotationConfigApplicationContext newContext() {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        Map<String, Object> properties = new HashMap<>();
        properties.put("server.broker.port", 11883);
        properties.put("fastbee.mqtt.server-username", USERNAME);
        properties.put("fastbee.mqtt.server-password", "");
        properties.put("fastbee.mqtt.callback-token", "");
        context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("mqtt-test", properties));
        context.register(MqttClientConfig.class);
        context.refresh();
        return context;
    }

    private static MqttClientConfig config(String password, String callbackToken) {
        MqttClientConfig config = new MqttClientConfig();
        config.setUsername(USERNAME);
        config.setPassword(password);
        config.setCallbackToken(callbackToken);
        config.initialize();
        return config;
    }

    private static ToolController controller(MqttClientConfig config, IToolService tool) throws Exception {
        ToolController controller = new ToolController();
        inject(controller, "mqttConfig", config);
        inject(controller, "toolService", tool);
        return controller;
    }

    private static void inject(Object target, String fieldName, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }

    private static JSONObject request(String clientId, String username, String password) {
        JSONObject json = new JSONObject();
        json.put("clientid", clientId);
        json.put("username", username);
        json.put("password", password);
        return json;
    }

    private static void assertLegacyDenied(ResponseEntity<?> response) {
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals("Unauthorized", response.getBody());
    }

    private static void assertV5Result(ResponseEntity<?> response, String expected) {
        assertEquals(HttpStatus.OK, response.getStatusCode());
        JSONObject body = (JSONObject) response.getBody();
        assertEquals(expected, body.getString("result"));
        assertEquals(Boolean.FALSE, body.getBoolean("is_superuser"));
    }
}
