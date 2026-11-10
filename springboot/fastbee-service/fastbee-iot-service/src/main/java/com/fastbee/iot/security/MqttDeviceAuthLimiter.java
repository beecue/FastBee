package com.fastbee.iot.security;

import com.google.common.hash.Hashing;
import com.google.common.net.InetAddresses;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/** Limits failed device logins without blocking a product for clients at other addresses. */
@Component
public class MqttDeviceAuthLimiter {
    private static final DefaultRedisScript<Long> RECORD_FAILURE = new DefaultRedisScript<>(
            "for i = 1, #KEYS do "
                    + "local failures = redis.call('INCR', KEYS[i]); "
                    + "if failures == 1 then redis.call('EXPIRE', KEYS[i], ARGV[1]); end "
                    + "end; return 1", Long.class);

    private final StringRedisTemplate redis;
    private final int deviceMaxFailures;
    private final int productMaxFailures;
    private final int windowSeconds;

    public MqttDeviceAuthLimiter(StringRedisTemplate redis,
                                @Value("${fastbee.mqtt.device-auth.max-failures:10}") int deviceMaxFailures,
                                @Value("${fastbee.mqtt.device-auth.source-product-max-failures:100}") int productMaxFailures,
                                @Value("${fastbee.mqtt.device-auth.window-seconds:60}") int windowSeconds) {
        if (deviceMaxFailures < 1 || productMaxFailures < deviceMaxFailures || windowSeconds < 1) {
            throw new IllegalArgumentException("Invalid MQTT device authentication limits");
        }
        this.redis = redis;
        this.deviceMaxFailures = deviceMaxFailures;
        this.productMaxFailures = productMaxFailures;
        this.windowSeconds = windowSeconds;
    }

    public List<String> failureKeys(String peer, Long productId, String serialNumber) {
        // Both counters share a slot when Redis Cluster is used.
        String scope = "mqtt:auth:fail:{" + normalizePeer(peer) + "/" + productId + "}:";
        String serialHash = Hashing.sha256().hashString(serialNumber, StandardCharsets.UTF_8).toString();
        return Arrays.asList(scope + "device:" + serialHash, scope + "product");
    }

    public boolean isBlocked(List<String> keys) {
        List<String> counts = redis.opsForValue().multiGet(keys);
        if (counts == null || counts.size() != keys.size()) {
            throw new IllegalStateException("Cannot read MQTT device authentication limits");
        }
        return atLimit(counts.get(0), deviceMaxFailures) || atLimit(counts.get(1), productMaxFailures);
    }

    public void recordFailure(List<String> keys) {
        redis.execute(RECORD_FAILURE, keys, Integer.toString(windowSeconds));
    }

    private static boolean atLimit(String count, int limit) {
        return count != null && Long.parseLong(count) >= limit;
    }

    private static String normalizePeer(String peer) {
        if (peer != null && peer.length() <= 64) {
            String address = peer.trim().split("%", 2)[0];
            if (InetAddresses.isInetAddress(address)) {
                return InetAddresses.toAddrString(InetAddresses.forString(address));
            }
        }
        // Older authenticated broker callbacks may omit the original MQTT peer.
        return "unknown";
    }
}
