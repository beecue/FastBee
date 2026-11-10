package com.fastbee.mqttclient;

import com.fastbee.common.utils.uuid.UUID;
import lombok.Data;
import lombok.ToString;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * mqtt配置信息
 */

@Data
@Component
public class MqttClientConfig {
    private static final int MIN_SECRET_LENGTH = 32;

    @Value("${server.broker.port}")
    private int port;

    @PostConstruct
    public void initialize() {
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalStateException("fastbee.mqtt.server-username must be set");
        }
        if (password == null || password.isEmpty()) {
            byte[] secret = new byte[32];
            new SecureRandom().nextBytes(secret);
            password = Base64.getUrlEncoder().withoutPadding().encodeToString(secret);
        } else if (password.trim().length() < MIN_SECRET_LENGTH) {
            throw new IllegalStateException("fastbee.mqtt.server-password must be at least 32 characters");
        }
        if (callbackToken != null && !callbackToken.isEmpty()
                && (callbackToken.trim().length() < MIN_SECRET_LENGTH || secretMatches(password, callbackToken))) {
            throw new IllegalStateException("fastbee.mqtt.callback-token must be at least 32 characters and different from the server password");
        }
        this.hostUrl = "tcp://127.0.0.1:" + port;
        this.clientId = UUID.randomUUID().toString();
        this.defaultTopic = "test";
        this.timeout = 30;
        this.keepalive = 30;
        this.clearSession = true;
        this.enabled = true;
    }

    public boolean matchesServerCredentials(String username, String password) {
        return this.username != null && this.username.equals(username) && secretMatches(this.password, password);
    }

    public boolean isTrustedCallback(String token) {
        return secretMatches(callbackToken, token);
    }

    private static boolean secretMatches(String expected, String supplied) {
        return expected != null && !expected.isEmpty() && supplied != null
                && MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), supplied.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 平台服务端 MQTT 账号，与设备产品凭据独立。
     */
    @Value("${fastbee.mqtt.server-username:fastbee-server}")
    private String username;
    /**
     * 密码
     */
    @Value("${fastbee.mqtt.server-password:}")
    @ToString.Exclude
    private String password;

    /** 仅外置 Broker 的 HTTP 认证回调使用，空值表示关闭认证回调。 */
    @Value("${fastbee.mqtt.callback-token:}")
    @ToString.Exclude
    private String callbackToken;
    /**
     * 连接地址
     */
    private String hostUrl;
    /**
     * 客户Id
     */
    private String clientId;
    /**
     * 默认连接话题
     */
    private String defaultTopic;
    /**
     * 超时时间
     */
    private int timeout;
    /**
     * 保持连接数
     */
    private int keepalive;

    /**
     * 是否清除session
     */
    private boolean clearSession;
    /**
     * 是否共享订阅
     */
    private boolean isShared;
    /**
     * 分组共享订阅
     */
    private boolean isSharedGroup;

    /**
     * true: 使用netty搭建的mqttBroker  false: 使用emq
     */
    private Boolean enabled;

}

