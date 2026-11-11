package com.fastbee.sip.service;

import com.fastbee.sip.domain.MediaServer;
import com.fastbee.sip.mapper.MediaServerMapper;
import com.fastbee.sip.model.VideoSessionInfo;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

@Component
public class MediaAccessTokens {
    private static final String HOOK_KEY = "sip:media:hook:";
    private static final String PLAY_KEY = "sip:media:play:";
    private static final String PLAY_PARAM = "playToken";
    private static final Pattern TOKEN = Pattern.compile("[0-9a-f]{32}");
    private static final Duration PLAY_TTL = Duration.ofMinutes(5);

    private final StringRedisTemplate redis;
    private final MediaServerMapper mediaServerMapper;

    public MediaAccessTokens(StringRedisTemplate redis, MediaServerMapper mediaServerMapper) {
        this.redis = redis;
        this.mediaServerMapper = mediaServerMapper;
    }

    public String provisionHookToken(MediaServer node) {
        String key = hookKey(node);
        String token = redis.opsForValue().get(key);
        if (token != null) {
            return token;
        }
        token = newToken();
        return Boolean.TRUE.equals(redis.opsForValue().setIfAbsent(key, token))
                ? token : redis.opsForValue().get(key);
    }

    public boolean allowsHook(String nodeId, String token) {
        if (nodeId == null || nodeId.isEmpty() || nodeId.length() > 128 || !validToken(token)) {
            return false;
        }
        MediaServer query = new MediaServer();
        query.setServerId(nodeId);
        List<MediaServer> nodes = mediaServerMapper.selectMediaServerList(query);
        if (nodes.size() != 1 || !nodeId.equals(nodes.get(0).getServerId())) {
            return false;
        }
        String expected = redis.opsForValue().get(hookKey(nodes.get(0)));
        return expected != null && MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.US_ASCII), token.getBytes(StandardCharsets.US_ASCII));
    }

    public String issuePlayback(VideoSessionInfo session) {
        String token = newToken();
        redis.opsForValue().set(PLAY_KEY + token, playbackScope(session), PLAY_TTL);
        return token;
    }

    public String playbackUrl(String url, String token) {
        return url == null ? null : url + (url.contains("?") ? "&" : "?") + PLAY_PARAM + "=" + token;
    }

    public boolean allowsPlayback(String params, VideoSessionInfo session) {
        if (params == null || session == null) {
            return false;
        }
        String query = params.startsWith("?") ? params.substring(1) : params;
        String token = null;
        String prefix = PLAY_PARAM + "=";
        for (String part : query.split("&")) {
            if (part.startsWith(prefix)) {
                if (token != null) {
                    return false;
                }
                token = part.substring(prefix.length());
            }
        }
        return validToken(token) && playbackScope(session).equals(redis.opsForValue().get(PLAY_KEY + token));
    }

    private static String playbackScope(VideoSessionInfo session) {
        return session.getMediaServerId() + "/" + session.getStream() + "/" + session.getSsrc();
    }

    private static String hookKey(MediaServer node) {
        return HOOK_KEY + node.getTenantId() + ":" + node.getServerId();
    }

    private static boolean validToken(String token) {
        return token != null && TOKEN.matcher(token).matches();
    }

    private static String newToken() {
        return UUID.randomUUID().toString().replace("-", "");
    }
}
