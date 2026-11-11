package com.fastbee.security;

import com.alibaba.fastjson2.JSONObject;
import com.fastbee.common.core.thingsModel.ThingsModelSimpleItem;
import com.fastbee.data.controller.ToolController;
import com.fastbee.iot.domain.Device;
import com.fastbee.iot.mapper.DeviceMapper;
import com.fastbee.iot.model.MqttClientConnectModel;
import com.fastbee.iot.model.ThingsModels.ThingsModelShadow;
import com.fastbee.iot.service.IDeviceService;
import com.fastbee.iot.service.impl.DeviceServiceImpl;
import com.fastbee.iot.tsdb.service.ILogService;
import com.fastbee.mq.service.IMqttMessagePublish;
import com.fastbee.mqttclient.MqttClientConfig;
import org.junit.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.http.HttpStatus;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class MqttWebhookSecurityTest {
    private static final long PRODUCT = 12L;
    private static final String SERIAL = "test-device";
    private static final String CLIENT = "S&" + SERIAL + "&" + PRODUCT + "&34";
    private static final String SERVER_PASSWORD = "test-only-server-password-0123456789";
    private static final String AUTH_TOKEN = "test-only-authentication-token-0123456789";
    private static final String WEBHOOK_TOKEN = "test-only-event-webhook-token-0123456789";

    @Test
    public void configuredWebhookTokenIsIndependentOfAuthenticationAndServerPassword() {
        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            Map<String, Object> properties = new HashMap<>();
            properties.put("server.broker.port", 11883);
            properties.put("fastbee.mqtt.server-password", SERVER_PASSWORD);
            properties.put("fastbee.mqtt.callback-token", AUTH_TOKEN);
            properties.put("fastbee.mqtt.webhook-token", WEBHOOK_TOKEN);
            context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("mqtt-webhook-test", properties));
            context.register(MqttClientConfig.class);
            context.refresh();
            MqttClientConfig config = context.getBean(MqttClientConfig.class);

            assertTrue(config.isTrustedWebhook(WEBHOOK_TOKEN));
            assertFalse(config.isTrustedWebhook(AUTH_TOKEN));
            assertFalse(config.isTrustedCallback(WEBHOOK_TOKEN));
            assertTrue(config.isTrustedCallback(AUTH_TOKEN));
            assertFalse(config.toString().contains(WEBHOOK_TOKEN));
        }
        assertThrows(IllegalStateException.class, () -> config("short"));
        assertThrows(IllegalStateException.class, () -> config(SERVER_PASSWORD));
        assertThrows(IllegalStateException.class, () -> config(AUTH_TOKEN));
    }

    @Test
    public void missingWrongOrUnconfiguredTokenHasNoBusinessSideEffects() throws Exception {
        Fixture fixture = new Fixture(WEBHOOK_TOKEN);
        for (String invalid : new String[]{null, "", "invalid-token", AUTH_TOKEN}) {
            assertEquals(HttpStatus.UNAUTHORIZED, fixture.controller
                    .webHookProcess(invalid, legacy("client_connected", "192.0.2.1")).getStatusCode());
            assertEquals(HttpStatus.UNAUTHORIZED, fixture.controller
                    .webHookProcessv5(invalid, event("session.subscribed", CLIENT, null)).getStatusCode());
        }
        verifyNoInteractions(fixture.devices, fixture.publisher);

        Fixture disabled = new Fixture("");
        assertEquals(HttpStatus.UNAUTHORIZED, disabled.controller
                .webHookProcess(WEBHOOK_TOKEN, legacy("client_disconnected", null)).getStatusCode());
        assertEquals(HttpStatus.UNAUTHORIZED, disabled.controller
                .webHookProcessv5(WEBHOOK_TOKEN, event("client.connected", CLIENT, null)).getStatusCode());
        verifyNoInteractions(disabled.devices, disabled.publisher);
    }

    @Test
    public void legacyWebhookStillBroadcastsStatusAndPublishesShadowOnConnection() throws Exception {
        Fixture fixture = new Fixture(WEBHOOK_TOKEN);
        assertEquals(HttpStatus.OK, fixture.controller
                .webHookProcess(WEBHOOK_TOKEN, legacy("client_connected", "192.0.2.1")).getStatusCode());
        assertEquals(Integer.valueOf(3), fixture.device.getStatus());
        verify(fixture.devices).updateDeviceStatusAndLocation(fixture.device, "192.0.2.1");
        verify(fixture.publisher).publishStatus(PRODUCT, SERIAL, 3, 1, 20);
        fixture.verifyShadow();

        assertEquals(HttpStatus.OK, fixture.controller
                .webHookProcess(WEBHOOK_TOKEN, legacy("client_disconnected", null)).getStatusCode());
        fixture.verifyDisconnected();
    }

    @Test
    public void v5StillPublishesShadowOnSubscriptionAndAcceptsOfflineWithoutPeerAddress() throws Exception {
        Fixture fixture = new Fixture(WEBHOOK_TOKEN);
        assertEquals(HttpStatus.OK, fixture.controller
                .webHookProcessv5(WEBHOOK_TOKEN, event("client.connected", CLIENT, "[2001:db8::12]:1883")).getStatusCode());
        assertEquals(Integer.valueOf(3), fixture.device.getStatus());
        verify(fixture.devices).updateDeviceStatusAndLocation(fixture.device, "2001:db8::12");
        verify(fixture.publisher).publishStatus(PRODUCT, SERIAL, 3, 1, 20);
        verify(fixture.devices, never()).getDeviceShadowThingsModel(any());

        assertEquals(HttpStatus.OK, fixture.controller
                .webHookProcessv5(WEBHOOK_TOKEN, event("session.subscribed", CLIENT, null)).getStatusCode());
        fixture.verifyShadow();
        verify(fixture.devices, times(1)).updateDeviceStatusAndLocation(any(), anyString());
        assertEquals(HttpStatus.OK, fixture.controller
                .webHookProcessv5(WEBHOOK_TOKEN, event("client.disconnected", CLIENT, null)).getStatusCode());
        fixture.verifyDisconnected();
    }

    @Test
    public void malformedPeerDoesNotPreventStatusUpdatesOrOverwriteDeviceAddress() throws Exception {
        Fixture fixture = new Fixture(WEBHOOK_TOKEN);
        fixture.controller.webHookProcessv5(WEBHOOK_TOKEN, event("client.connected", CLIENT, "invalid-address"));
        assertEquals(Integer.valueOf(3), fixture.device.getStatus());
        verify(fixture.devices).updateDeviceStatusAndLocation(fixture.device, "");
        verify(fixture.publisher).publishStatus(PRODUCT, SERIAL, 3, 1, 20);
    }

    @Test
    public void olderDevicesWithNoLocationModeCanStillChangeStatus() throws Exception {
        DeviceServiceImpl service = new DeviceServiceImpl();
        DeviceMapper mapper = mock(DeviceMapper.class);
        inject(service, "deviceMapper", mapper);
        inject(service, "logService", mock(ILogService.class));
        Device device = new Device();
        device.setStatus(3);
        device.setNetworkIp("192.0.2.1");

        service.updateDeviceStatusAndLocation(device, "192.0.2.2");
        assertEquals("192.0.2.1", device.getNetworkIp());
        device.setLocationWay(1);
        service.updateDeviceStatusAndLocation(device, "");
        assertEquals("192.0.2.1", device.getNetworkIp());
        service.updateDeviceStatusAndLocation(device, "192.0.2.2");
        assertEquals("192.0.2.2", device.getNetworkIp());
        verify(mapper, times(3)).updateDeviceStatus(device);
    }

    @Test
    public void ignoresUnrelatedClientsAndChecksProductWhenTheClientIdHasTheStandardFormat() throws Exception {
        Fixture fixture = new Fixture(WEBHOOK_TOKEN);
        fixture.controller.webHookProcessv5(WEBHOOK_TOKEN, event("client.connected", "server-test", null));
        fixture.controller.webHookProcessv5(WEBHOOK_TOKEN, event("other", CLIENT, null));
        fixture.controller.webHookProcessv5(WEBHOOK_TOKEN, event("client.connected", "missing-device", null));
        verifyNoInteractions(fixture.devices, fixture.publisher);

        fixture.controller.webHookProcessv5(WEBHOOK_TOKEN, event("client.connected", "S&" + SERIAL + "&99&34", null));
        verify(fixture.devices).selectShortDeviceBySerialNumber(SERIAL);
        verifyNoMoreInteractions(fixture.devices);
        verifyNoInteractions(fixture.publisher);

        fixture.controller.webHookProcessv5(WEBHOOK_TOKEN, event("client.connected", "S&" + SERIAL, "192.0.2.1:1883"));
        verify(fixture.devices).updateDeviceStatusAndLocation(fixture.device, "192.0.2.1");
        fixture.device.setStatus(2);
        fixture.controller.webHookProcess(WEBHOOK_TOKEN, legacy("client_disconnected", null));
        assertEquals(Integer.valueOf(2), fixture.device.getStatus());
        verify(fixture.devices, never()).updateDeviceStatusAndLocation(any(), eq(""));
    }

    private static MqttClientConfig config(String token) {
        MqttClientConfig config = new MqttClientConfig();
        config.setUsername("test-server");
        config.setPassword(SERVER_PASSWORD);
        config.setCallbackToken(AUTH_TOKEN);
        config.setWebhookToken(token);
        config.initialize();
        return config;
    }

    private static MqttClientConnectModel legacy(String action, String address) {
        MqttClientConnectModel model = new MqttClientConnectModel();
        model.setAction(action);
        model.setClientid(CLIENT);
        model.setIpaddress(address);
        return model;
    }

    private static JSONObject event(String event, String client, String peer) {
        JSONObject json = new JSONObject();
        json.put("event", event);
        json.put("clientid", client);
        if (peer != null) {
            json.put("peername", peer);
        }
        return json;
    }

    private static void inject(Object target, String fieldName, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }

    private static class Fixture {
        private final IDeviceService devices = mock(IDeviceService.class);
        private final IMqttMessagePublish publisher = mock(IMqttMessagePublish.class);
        private final ToolController controller = new ToolController();
        private final Device device = new Device();
        private final ThingsModelShadow shadow = new ThingsModelShadow(
                Collections.singletonList(new ThingsModelSimpleItem()), Collections.singletonList(new ThingsModelSimpleItem()));

        Fixture(String token) throws Exception {
            device.setProductId(PRODUCT);
            device.setSerialNumber(SERIAL);
            device.setStatus(4);
            device.setIsShadow(1);
            device.setRssi(20);
            when(devices.selectShortDeviceBySerialNumber(SERIAL)).thenReturn(device);
            when(devices.getDeviceShadowThingsModel(device)).thenReturn(shadow);
            inject(controller, "mqttConfig", config(token));
            inject(controller, "deviceService", devices);
            inject(controller, "messagePublish", publisher);
        }

        void verifyShadow() {
            verify(publisher).publishProperty(PRODUCT, SERIAL, shadow.getProperties(), 3);
            verify(publisher).publishFunction(PRODUCT, SERIAL, shadow.getFunctions(), 3);
        }

        void verifyDisconnected() {
            assertEquals(Integer.valueOf(4), device.getStatus());
            verify(devices).updateDeviceStatusAndLocation(device, "");
            verify(publisher).publishStatus(PRODUCT, SERIAL, 4, 1, 20);
            verify(publisher).publishProperty(PRODUCT, SERIAL, null, 0);
            verify(publisher).publishFunction(PRODUCT, SERIAL, null, 0);
        }

    }
}
