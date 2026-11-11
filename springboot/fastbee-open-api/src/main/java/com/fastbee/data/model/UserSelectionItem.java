package com.fastbee.data.model;

import com.fastbee.common.core.domain.entity.SysUser;
import com.fastbee.common.utils.StringUtils;
import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Getter;

import java.util.Date;

@Getter
public final class UserSelectionItem {
    private final Long userId;
    private final String userName;
    private final String nickName;
    private final String phonenumber;
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private final Date createTime;

    public UserSelectionItem(SysUser user) {
        this.userId = user.getUserId();
        this.userName = user.getUserName();
        this.nickName = user.getNickName();
        this.phonenumber = maskPhone(user.getPhonenumber());
        this.createTime = user.getCreateTime();
    }

    private static String maskPhone(String phone) {
        if (StringUtils.isEmpty(phone)) {
            return phone;
        }
        return phone.matches("[0-9]{11}") ? StringUtils.hide(phone, 3, 7) : StringUtils.hide(phone, 0, phone.length());
    }
}
