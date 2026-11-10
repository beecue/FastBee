package com.fastbee.data.acl;

import com.fastbee.common.core.domain.entity.SysUser;
import com.fastbee.common.core.domain.model.LoginUser;
import com.fastbee.common.exception.ServiceException;
import com.fastbee.common.utils.SecurityUtils;
import com.fastbee.iot.domain.Device;
import com.fastbee.iot.domain.DeviceUser;
import com.fastbee.iot.domain.Product;
import com.fastbee.iot.mapper.DeviceMapper;
import com.fastbee.iot.mapper.DeviceUserMapper;
import com.fastbee.iot.mapper.ProductMapper;
import com.fastbee.iot.security.IotCredentialAccess;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.Objects;

/**
 * 按 ID 直取单条记录的接口必须复用列表接口的归属范围。
 * 列表查询在 Service 层按角色注入 tenantId/userId，而详情、凭据、修改、删除接口此前只校验权限字符串，
 * 配合自增主键可被遍历读取/操作他人数据。校验放在控制器边界：Service 方法同时被 MQTT broker
 * 线程和内部流程调用，那里没有登录态。
 */
@Component
public class IotDataAccessGuard {

    /* RuoYi 数据范围 1=全部数据权限，种子中 admin/manager/visitor 持有，保持其原有全局可见行为 */
    private static final String DATA_SCOPE_ALL = "1";

    @Resource
    private DeviceMapper deviceMapper;
    @Resource
    private DeviceUserMapper deviceUserMapper;
    @Resource
    private ProductMapper productMapper;

    public void assertDeviceAccessible(Long deviceId) {
        checkDevice(deviceMapper.selectDeviceByDeviceId(deviceId));
    }

    public void assertDeviceAccessibleBySerialNumber(String serialNumber) {
        checkDevice(deviceMapper.selectDeviceBySerialNumber(serialNumber));
    }

    public void assertProductAccessible(Long productId) {
        assertProductAccessible(productMapper.selectProductByProductId(productId));
    }

    public void assertProductAccessible(Product product) {
        if (product != null && !IotCredentialAccess.canManageProduct(currentUser(), product)) {
            throw new ServiceException("无权访问其他租户的产品");
        }
    }

    private void checkDevice(Device device) {
        if (device == null) {
            return;
        }
        SysUser user = currentUser();
        if (isGlobal(user)
                || Objects.equals(device.getUserId(), user.getUserId())
                || Objects.equals(device.getTenantId(), user.getUserId())
                || isShared(device.getDeviceId(), user.getUserId())) {
            return;
        }
        throw new ServiceException("无权访问其他用户的设备");
    }

    private boolean isShared(Long deviceId, Long userId) {
        DeviceUser share = deviceUserMapper.selectDeviceUserByDeviceIdAndUserId(deviceId, userId);
        return share != null && !"2".equals(share.getDelFlag());
    }

    private boolean isGlobal(SysUser user) {
        if (user.isAdmin()) {
            return true;
        }
        return user.getRoles() != null && user.getRoles().stream()
                .anyMatch(role -> DATA_SCOPE_ALL.equals(role.getDataScope()));
    }

    private SysUser currentUser() {
        LoginUser loginUser = SecurityUtils.getLoginUser();
        if (loginUser == null || loginUser.getUser() == null) {
            throw new ServiceException("登录状态已失效，请重新登录");
        }
        return loginUser.getUser();
    }
}
