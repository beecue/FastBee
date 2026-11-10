package com.fastbee.iot.security;

import com.fastbee.common.core.domain.entity.SysUser;
import com.fastbee.iot.domain.Device;
import com.fastbee.iot.domain.Product;

import java.util.Objects;

public final class IotCredentialAccess {

    private IotCredentialAccess() {
    }

    public static boolean isPlatformManager(SysUser user) {
        return user.isAdmin() || (user.getRoles() != null && user.getRoles().stream()
                .anyMatch(role -> "manager".equals(role.getRoleKey())
                        && "1".equals(role.getDataScope()) && "0".equals(role.getStatus())));
    }

    /** A null scope is reserved for platform managers. */
    public static Long managedTenantId(SysUser user) {
        return isPlatformManager(user) ? null : Objects.requireNonNull(user.getUserId());
    }

    public static boolean canManageProduct(SysUser user, Product product) {
        return isPlatformManager(user) || Objects.requireNonNull(user.getUserId()).equals(product.getTenantId());
    }

    public static boolean canUseProduct(SysUser user, Product product) {
        return !"2".equals(product.getDelFlag()) && (canManageProduct(user, product)
                || (Integer.valueOf(1).equals(product.getIsSys()) && Integer.valueOf(2).equals(product.getStatus())));
    }

    public static boolean canManageDevice(SysUser user, Device device) {
        return isPlatformManager(user)
                || Objects.requireNonNull(user.getUserId()).equals(device.getUserId())
                || user.getUserId().equals(device.getTenantId());
    }
}
