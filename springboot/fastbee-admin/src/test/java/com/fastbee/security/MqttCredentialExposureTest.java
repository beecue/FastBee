package com.fastbee.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fastbee.common.core.domain.entity.SysRole;
import com.fastbee.common.core.domain.entity.SysUser;
import com.fastbee.common.core.domain.model.LoginUser;
import com.fastbee.common.exception.ServiceException;
import com.fastbee.data.acl.IotDataAccessGuard;
import com.fastbee.iot.domain.Device;
import com.fastbee.iot.domain.Product;
import com.fastbee.iot.mapper.DeviceMapper;
import com.fastbee.iot.mapper.ProductMapper;
import com.fastbee.iot.model.DeviceMqttVO;
import com.fastbee.iot.model.DeviceNumberAndProductId;
import com.fastbee.iot.model.DeviceRelateUserInput;
import com.fastbee.iot.service.IProductService;
import com.fastbee.iot.service.impl.DeviceServiceImpl;
import com.fastbee.iot.service.impl.ProductServiceImpl;
import com.fastbee.system.service.ISysUserService;
import org.apache.ibatis.builder.xml.XMLMapperBuilder;
import org.apache.ibatis.io.Resources;
import org.apache.ibatis.session.Configuration;
import org.junit.After;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class MqttCredentialExposureTest {

    @After
    public void clearLogin() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void visitorScopeAndClientFilterCannotExpandProductList() throws Exception {
        login(42L, "visitor", "1");
        ProductMapper mapper = mock(ProductMapper.class);
        ProductServiceImpl service = new ProductServiceImpl();
        inject(service, "productMapper", mapper);
        Product filter = new Product();
        filter.setTenantId(99L);

        service.selectProductList(filter);
        service.selectAvailableProductList(filter);

        verify(mapper).selectProductList(filter, 42L, false);
        verify(mapper).selectProductList(filter, 42L, true);
    }

    @Test
    public void productListSqlAndJsonOmitCredentials() throws Exception {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("product", new Product());
        parameters.put("ownerId", 42L);
        parameters.put("includeSystem", false);
        String statement = ProductMapper.class.getName() + ".selectProductList";
        Configuration configuration = loadMapper("mapper/iot/ProductMapper.xml");
        String listSql = sql(configuration, statement, parameters);
        assertTrue(listSql.contains("tenant_id = ?"));
        assertFalse(listSql.contains("is_sys = 1"));
        assertFalse(listSql.contains("mqtt_account"));
        assertFalse(listSql.contains("mqtt_password"));
        assertFalse(listSql.contains("mqtt_secret"));

        parameters.put("includeSystem", true);
        assertTrue(sql(configuration, statement, parameters).contains("or (is_sys = 1 and status = 2"));

        JsonNode json = new ObjectMapper().valueToTree(new Product());
        assertFalse(json.has("mqttAccount"));
        assertFalse(json.has("mqttPassword"));
        assertFalse(json.has("mqttSecret"));
    }

    @Test
    public void productDetailsAllowProductOwnerButDenyForeignVisitor() {
        Product product = new Product();
        product.setTenantId(99L);
        IotDataAccessGuard guard = new IotDataAccessGuard();
        login(42L, "visitor", "1");
        assertThrows(ServiceException.class, () -> guard.assertProductAccessible(product));

        login(99L, "tenant", "5");
        guard.assertProductAccessible(product);
    }

    @Test
    public void credentialsRequireProductAndDeviceScopeInSameQuery() throws Exception {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("deviceId", 9L);
        parameters.put("tenantId", 42L);
        Configuration configuration = loadMapper("mapper/iot/DeviceMapper.xml");
        String statement = DeviceMapper.class.getName() + ".selectMqttConnectData";
        String scopedSql = sql(configuration, statement, parameters);
        assertTrue(scopedSql.contains("and p.tenant_id = ? and (d.tenant_id = ? or d.user_id = ?)"));
        assertFalse(scopedSql.contains("mqtt_secret"));

        parameters.put("tenantId", null);
        assertFalse(sql(configuration, statement, parameters).contains("p.tenant_id = ?"));
    }

    @Test
    public void visitorCannotReadForeignDeviceCredentialsButManagerCan() throws Exception {
        DeviceMapper mapper = mock(DeviceMapper.class);
        DeviceServiceImpl service = new DeviceServiceImpl();
        inject(service, "deviceMapper", mapper);
        login(42L, "visitor", "1");
        ServiceException denied = assertThrows(ServiceException.class, () -> service.getMqttConnectData(9L));
        assertEquals(Integer.valueOf(403), denied.getCode());
        verify(mapper).selectMqttConnectData(9L, 42L);

        DeviceMqttVO mqtt = new DeviceMqttVO();
        mqtt.setProductId(8L);
        mqtt.setUserId(99L);
        mqtt.setSerialNumber("device-under-test");
        mqtt.setMqttPassword("local-test-password");
        when(mapper.selectMqttConnectData(9L, null)).thenReturn(mqtt);
        login(55L, "manager", "1");
        assertEquals("local-test-password", service.getMqttConnectData(9L).getPasswd());
    }

    @Test
    public void foreignDeviceCannotBeClaimedAndForeignPrivateProductCannotBeBound() throws Exception {
        SysUser caller = login(42L, "general", "5");
        DeviceMapper devices = mock(DeviceMapper.class);
        ISysUserService users = mock(ISysUserService.class);
        IProductService products = mock(IProductService.class);
        DeviceServiceImpl service = new DeviceServiceImpl();
        inject(service, "deviceMapper", devices);
        inject(service, "userService", users);
        inject(service, "productService", products);
        when(users.selectUserById(42L)).thenReturn(caller);
        Device foreign = new Device();
        foreign.setUserId(99L);
        foreign.setTenantId(99L);
        when(devices.selectDeviceBySerialNumber("foreign")).thenReturn(foreign);
        DeviceRelateUserInput transfer = new DeviceRelateUserInput(42L,
                Collections.singletonList(new DeviceNumberAndProductId(8L, "foreign")));
        assertThrows(ServiceException.class, () -> service.deviceRelateUser(transfer));
        verify(devices, never()).transferDeviceOwner(any(), any(), any());

        Product privateProduct = new Product();
        privateProduct.setTenantId(99L);
        privateProduct.setIsSys(0);
        privateProduct.setStatus(2);
        when(products.selectProductByProductId(8L)).thenReturn(privateProduct);
        Device newDevice = new Device();
        newDevice.setSerialNumber("new-device");
        newDevice.setProductId(8L);
        assertThrows(ServiceException.class, () -> service.insertDevice(newDevice));
        verify(devices, never()).insertDevice(any());
    }

    private SysUser login(Long userId, String roleKey, String dataScope) {
        SysRole role = new SysRole();
        role.setRoleKey(roleKey);
        role.setDataScope(dataScope);
        role.setStatus("0");
        SysUser user = new SysUser();
        user.setUserId(userId);
        user.setRoles(Collections.singletonList(role));
        LoginUser login = new LoginUser(userId, 1L, user, Collections.emptySet());
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(login, null, Collections.emptyList()));
        return user;
    }

    private void inject(Object target, String fieldName, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }

    private Configuration loadMapper(String resource) throws Exception {
        Configuration configuration = new Configuration();
        try (InputStream xml = Resources.getResourceAsStream(resource)) {
            new XMLMapperBuilder(xml, configuration, resource, configuration.getSqlFragments()).parse();
        }
        return configuration;
    }

    private String sql(Configuration configuration, String statement, Map<String, Object> parameters) {
        return configuration.getMappedStatement(statement).getBoundSql(parameters).getSql()
                .replaceAll("\\s+", " ").trim();
    }
}
