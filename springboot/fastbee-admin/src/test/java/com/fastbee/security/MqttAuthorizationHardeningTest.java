package com.fastbee.security;

import com.alibaba.fastjson2.JSONObject;
import com.fastbee.base.session.Session;
import com.fastbee.base.util.AttributeUtils;
import com.fastbee.common.core.domain.model.MqttClientPrincipal;
import com.fastbee.common.enums.TopicType;
import com.fastbee.iot.model.ProductAuthenticateModel;
import com.fastbee.iot.security.MqttDeviceAuthLimiter;
import com.fastbee.iot.service.IDeviceService;
import com.fastbee.iot.service.impl.ToolServiceImpl;
import com.fastbee.iot.util.AESUtils;
import com.fastbee.mqtt.acl.MqttAccessControl;
import com.fastbee.mqtt.auth.AuthService;
import com.fastbee.mqtt.handler.MqttConnect;
import com.fastbee.mqtt.handler.MqttSubscribe;
import com.fastbee.mqtt.manager.ClientManager;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.mqtt.MqttConnAckMessage;
import io.netty.handler.codec.mqtt.MqttConnectReturnCode;
import io.netty.handler.codec.mqtt.MqttMessageBuilders;
import io.netty.handler.codec.mqtt.MqttQoS;
import io.netty.handler.codec.mqtt.MqttSubAckMessage;
import io.netty.handler.codec.mqtt.MqttVersion;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class MqttAuthorizationHardeningTest {
    private static final String PEER = "192.0.2.1";
    private static final String OTHER_PEER = "192.0.2.2";
    private static final String DEVICE = "S&device-a&41&1";
    private static final String OTHER_DEVICE = "S&device-b&41&1";
    private static final String USERNAME = "device-user";
    private static final String PASSWORD = "device-password";
    private static final MqttClientPrincipal SERVER =
            MqttClientPrincipal.of("server-regression", MqttClientPrincipal.ClientType.SERVER);

    @Test
    public void serverPolicyPreservesPlatformTopicsByDirectionAndBlocksBroaderFilters() {
        MqttAccessControl acl = new MqttAccessControl();
        for (TopicType type : TopicType.values()) {
            String topic = "/41/device-a" + type.getTopicSuffix();
            if (type.getType() == 0) {
                assertFalse(topic, acl.canSubscribe(SERVER, topic));
                assertFalse(acl.canSubscribe(SERVER, "/+/+" + type.getTopicSuffix()));
            } else {
                assertTrue(topic, acl.canPublish(SERVER, topic));
            }
        }
        assertFalse(acl.canSubscribe(SERVER, "#"));
        assertFalse(acl.canSubscribe(SERVER, "/+/+/#"));
        assertFalse(acl.canSubscribe(SERVER, "/41/device-a/function/get"));
        assertFalse(acl.canSubscribe(SERVER, "/41/device+a/property/post"));
        assertFalse(acl.canSubscribe(SERVER, "/anything/device-a/property/post"));
        assertFalse(acl.canPublish(SERVER, "/41/device-a/ntp/post"));
        assertFalse(acl.canPublish(SERVER, "/41/device-a/custom/test"));
        assertFalse(acl.canPublish(SERVER, "/+/device-a/function/get"));

        MqttClientPrincipal device = MqttClientPrincipal.of("device-a", MqttClientPrincipal.ClientType.DEVICE);
        assertTrue(acl.canPublish(device, "/41/device-a/property/post"));
        assertTrue(acl.canSubscribe(device, "/41/device-a/function/get"));
    }

    @Test
    public void exactExtraTopicsKeepCustomIntegrationsWorking() throws Exception {
        MqttAccessControl acl = new MqttAccessControl();
        Method publish = MqttAccessControl.class.getDeclaredMethod("setExtraServerPublishTopics", String.class);
        Method subscribe = MqttAccessControl.class.getDeclaredMethod("setExtraServerSubscribeTopics", String.class);
        publish.setAccessible(true);
        subscribe.setAccessible(true);
        publish.invoke(acl, "vendor/device-a/command, vendor/device-b/command");
        subscribe.invoke(acl, "vendor/device-a/reply");
        assertTrue(acl.canPublish(SERVER, "vendor/device-a/command"));
        assertTrue(acl.canSubscribe(SERVER, "vendor/device-a/reply"));
        assertFalse(acl.canSubscribe(SERVER, "vendor/device-a/command"));
        assertFalse(acl.canPublish(SERVER, "vendor/device-c/command"));
        assertFalse(acl.canSubscribe(SERVER, "vendor/+/reply"));
    }

    @Test
    public void serverCannotBypassPublishingRulesWithALastWill() throws Exception {
        MqttConnect handler = new MqttConnect();
        AuthService auth = mock(AuthService.class);
        when(auth.authenticate("server-regression", "server-user", "server-pass", "127.0.0.1")).thenReturn(SERVER);
        inject(handler, "authService", auth);
        inject(handler, "mqttAccessControl", new MqttAccessControl());
        ChannelHandlerContext context = mock(ChannelHandlerContext.class);
        Channel channel = mock(Channel.class);
        when(context.channel()).thenReturn(channel);
        when(channel.remoteAddress()).thenReturn(new InetSocketAddress("127.0.0.1", 25000));
        when(context.writeAndFlush(any())).thenReturn(mock(ChannelFuture.class));

        handler.handler(context, MqttMessageBuilders.connect().protocolVersion(MqttVersion.MQTT_3_1_1)
                .clientId("server-regression").hasUser(true).username("server-user")
                .hasPassword(true).password("server-pass").willFlag(true)
                .willTopic("/41/device-a/custom/test").willMessage("test").build());
        ArgumentCaptor<MqttConnAckMessage> response = ArgumentCaptor.forClass(MqttConnAckMessage.class);
        verify(context).writeAndFlush(response.capture());
        assertEquals(MqttConnectReturnCode.CONNECTION_REFUSED_NOT_AUTHORIZED,
                response.getValue().variableHeader().connectReturnCode());
        verify(context).close();
    }

    @Test
    public void serverReceivesSubackFailureForThePreviouslyAllowedTelemetryFilter() throws Exception {
        MqttSubscribe handler = new MqttSubscribe();
        inject(handler, "mqttAccessControl", new MqttAccessControl());
        EmbeddedChannel channel = new EmbeddedChannel();
        ChannelHandlerContext context = mock(ChannelHandlerContext.class);
        when(context.channel()).thenReturn(channel);
        when(context.writeAndFlush(any())).thenReturn(channel.newSucceededFuture());
        Session session = new Session();
        session.setClientId(SERVER.getClientId());
        session.setPrincipal(SERVER);
        session.setHandlerContext(context);
        AttributeUtils.setSession(channel, session);

        try {
            handler.subscribe(context, MqttMessageBuilders.subscribe().messageId(8)
                    .addSubscription(MqttQoS.AT_LEAST_ONCE, "/+/+/property/post").build());
            ArgumentCaptor<MqttSubAckMessage> response = ArgumentCaptor.forClass(MqttSubAckMessage.class);
            verify(context).writeAndFlush(response.capture());
            assertEquals(Collections.singletonList(128), response.getValue().payload().grantedQoSLevels());
        } finally {
            ClientManager.remove(SERVER.getClientId());
            channel.finishAndReleaseAll();
        }
    }

    @Test
    public void failingOneDeviceBlocksItsNextAttemptWithoutBlockingOtherDevicesOrPeers() throws Exception {
        Fixture fixture = new Fixture();

        assertEquals(HttpStatus.UNAUTHORIZED, fixture.service.clientAuth(DEVICE, USERNAME, "wrong", PEER).getStatusCode());
        assertV5(fixture.service.clientAuthv5(DEVICE, USERNAME, "wrong", PEER), "deny");
        assertV5(fixture.service.clientAuthv5(DEVICE, USERNAME, PASSWORD, PEER), "deny");
        verify(fixture.devices, times(2)).selectProductAuthenticate(any());

        assertEquals(HttpStatus.OK, fixture.service.clientAuth(OTHER_DEVICE, USERNAME, PASSWORD, PEER).getStatusCode());
        assertV5(fixture.service.clientAuthv5(DEVICE, USERNAME, PASSWORD, OTHER_PEER), "allow");
        fixture.seconds += 5;
        assertEquals(HttpStatus.OK, fixture.service.clientAuth(DEVICE, USERNAME, PASSWORD, PEER).getStatusCode());
    }

    @Test
    public void rotatingSerialNumbersCannotAvoidTheSourceProductLimit() throws Exception {
        Fixture fixture = new Fixture();
        for (int i = 0; i < 4; i++) {
            assertEquals(HttpStatus.UNAUTHORIZED,
                    fixture.service.clientAuth("S&wrong-" + i + "&41&1", USERNAME, "wrong", PEER).getStatusCode());
        }
        assertV5(fixture.service.clientAuthv5(DEVICE, USERNAME, PASSWORD, PEER), "deny");
        verify(fixture.devices, times(4)).selectProductAuthenticate(any());
        assertV5(fixture.service.clientAuthv5(DEVICE, USERNAME, PASSWORD, OTHER_PEER), "allow");
        assertV5(fixture.service.clientAuthv5("S&device-a&42&1", USERNAME, PASSWORD, PEER), "allow");
    }

    @Test
    public void successfulDeviceReconnectsDoNotSpendTheFailureBudget() throws Exception {
        Fixture fixture = new Fixture();
        for (int i = 0; i < 8; i++) {
            assertEquals(HttpStatus.OK, fixture.service.clientAuth(DEVICE, USERNAME, PASSWORD, PEER).getStatusCode());
        }
        assertTrue(fixture.failures.isEmpty());
    }

    @Test
    public void encryptedDeviceAuthenticationStillWorksInBothProtocols() throws Exception {
        Fixture fixture = new Fixture();
        fixture.model.setVertificateMethod(3);
        String secret = "0123456789abcdef";
        fixture.model.setMqttSecret(secret);
        String password = AESUtils.encrypt(PASSWORD + "&" + (System.currentTimeMillis() + 60000), secret);
        String deviceId = "E&device-a&41&1";

        assertEquals(HttpStatus.OK, fixture.service.clientAuth(deviceId, USERNAME, password, PEER).getStatusCode());
        assertV5(fixture.service.clientAuthv5(deviceId, USERNAME, password, PEER), "allow");
        assertTrue(fixture.failures.isEmpty());
    }

    private static void assertV5(ResponseEntity<?> response, String result) {
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(result, ((JSONObject) response.getBody()).getString("result"));
    }

    private static void inject(Object target, String fieldName, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }

    /** Redis mock with a controllable clock for checking authentication behavior across a lockout window. */
    private static class Fixture {
        private final Map<String, Integer> failures = new HashMap<>();
        private final Map<String, Long> expirations = new HashMap<>();
        private final IDeviceService devices = mock(IDeviceService.class);
        private final ToolServiceImpl service = new ToolServiceImpl();
        private final ProductAuthenticateModel model = new ProductAuthenticateModel();
        private long seconds;

        @SuppressWarnings("unchecked")
        Fixture() throws Exception {
            StringRedisTemplate redis = mock(StringRedisTemplate.class);
            ValueOperations<String, String> counters = mock(ValueOperations.class);
            when(redis.opsForValue()).thenReturn(counters);
            when(counters.multiGet(anyList())).thenAnswer(call -> {
                List<String> keys = call.getArgument(0);
                return keys.stream().map(key -> expires(key) ? null : failures.get(key).toString()).collect(Collectors.toList());
            });
            when(redis.execute(any(RedisScript.class), anyList(), anyString())).thenAnswer(call -> {
                List<String> keys = call.getArgument(1);
                int ttl = Integer.parseInt(call.getArgument(2));
                for (String key : keys) {
                    if (expires(key)) {
                        expirations.put(key, seconds + ttl);
                        failures.put(key, 0);
                    }
                    failures.merge(key, 1, Integer::sum);
                }
                return 1L;
            });
            inject(service, "deviceAuthLimiter", new MqttDeviceAuthLimiter(redis, 2, 4, 5));
            inject(service, "deviceService", devices);
            model.setProductStatus(2);
            model.setVertificateMethod(1);
            model.setIsAuthorize(0);
            model.setStatus(3);
            model.setDeviceId(12L);
            model.setMqttAccount(USERNAME);
            model.setMqttPassword(PASSWORD);
            when(devices.selectProductAuthenticate(any())).thenReturn(model);
        }

        private boolean expires(String key) {
            return expirations.getOrDefault(key, 0L) <= seconds;
        }

    }
}
