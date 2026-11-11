package com.fastbee.security;

import com.alibaba.fastjson.JSONObject;
import com.fastbee.common.annotation.RateLimiter;
import com.fastbee.common.core.domain.entity.SysUser;
import com.fastbee.common.core.domain.model.LoginUser;
import com.fastbee.data.controller.media.PlayerController;
import com.fastbee.data.controller.media.ZmlHookController;
import com.fastbee.framework.aspectj.RateLimiterAspect;
import com.fastbee.framework.web.service.PermissionService;
import com.fastbee.sip.domain.MediaServer;
import com.fastbee.sip.domain.SipDevice;
import com.fastbee.sip.domain.SipDeviceChannel;
import com.fastbee.sip.mapper.MediaServerMapper;
import com.fastbee.sip.mapper.SipDeviceChannelMapper;
import com.fastbee.sip.model.Stream;
import com.fastbee.sip.model.VideoSessionInfo;
import com.fastbee.sip.server.ISipCmd;
import com.fastbee.sip.server.VideoSessionManager;
import com.fastbee.sip.service.IMediaServerService;
import com.fastbee.sip.service.IPlayService;
import com.fastbee.sip.service.ISipDeviceService;
import com.fastbee.sip.service.IZmlHookService;
import com.fastbee.sip.service.MediaAccessTokens;
import com.fastbee.sip.service.impl.PlayServiceImpl;
import com.fastbee.sip.service.impl.ZmlHookServiceImpl;
import com.fastbee.sip.util.ZlmApiUtils;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.reflect.MethodSignature;
import org.junit.After;
import org.junit.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class SipVideoAuthorizationTest {
    private static final String DEVICE = "34020000001320000001";
    private static final String CHANNEL = "34020000001320000002";
    private static final String STREAM = "gb_play_" + DEVICE + "_" + CHANNEL;
    private static final String NODE = "test-media";

    @After
    public void clearAuthentication() {
        SecurityContextHolder.clearContext();
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    public void requiresVideoPermissionAndTheExactChannelBeforeAnySipOperation() {
        RequestContextHolder.setRequestAttributes(mock(RequestAttributes.class));
        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(PlayerTestConfig.class)) {
            PlayerController player = context.getBean(PlayerController.class);
            IPlayService play = context.getBean(IPlayService.class);
            SipDeviceChannelMapper channels = context.getBean(SipDeviceChannelMapper.class);

            login(21L, "iot:device:list");
            assertThrows(AccessDeniedException.class, () -> player.play(DEVICE, CHANNEL));
            assertThrows(AccessDeniedException.class, () -> player.getBigScreenUrl(DEVICE, CHANNEL));
            assertThrows(AccessDeniedException.class, () -> player.closeStream(DEVICE, CHANNEL, STREAM));
            verifyNoInteractions(channels, play);

            SipDeviceChannel channel = new SipDeviceChannel();
            channel.setDeviceSipId(DEVICE);
            channel.setChannelSipId(CHANNEL);
            channel.setTenantId(21L);
            when(channels.selectSipDeviceChannelList(any())).thenReturn(Collections.singletonList(channel));

            login(22L, "iot:video:list");
            assertThrows(AccessDeniedException.class, () -> player.play(DEVICE, CHANNEL));
            assertThrows(AccessDeniedException.class, () -> player.getBigScreenUrl(DEVICE, CHANNEL));
            assertThrows(AccessDeniedException.class, () -> player.closeStream(DEVICE, CHANNEL, STREAM));
            verifyNoInteractions(play);

            login(21L, "iot:video:list");
            assertThrows(AccessDeniedException.class, () -> player.play(DEVICE + "9", CHANNEL));
            verifyNoInteractions(play);
            assertEquals(500, player.getBigScreenUrl(DEVICE, CHANNEL).get("code"));

            Stream stream = new Stream();
            stream.setHttps_fmp4("https://example.invalid/media");
            when(play.play(DEVICE, CHANNEL, false)).thenReturn(stream);
            assertSame(stream, player.play(DEVICE, CHANNEL).get("data"));
            assertEquals(stream.getHttps_fmp4(), player.getBigScreenUrl(DEVICE, CHANNEL).get("data"));
            player.closeStream(DEVICE, CHANNEL, STREAM);
            verify(play).closeStream(DEVICE, CHANNEL, STREAM);
        }
    }

    @Test
    public void closesOnlyTheBoundStreamWithoutReadersAcrossProtocols() throws Exception {
        PlayServiceImpl play = new PlayServiceImpl();
        ISipCmd sip = mock(ISipCmd.class);
        VideoSessionManager sessions = mock(VideoSessionManager.class);
        IMediaServerService media = mock(IMediaServerService.class);
        ZlmApiUtils api = mock(ZlmApiUtils.class);
        ISipDeviceService devices = mock(ISipDeviceService.class);
        inject(play, "sipCmd", sip);
        inject(play, "streamSession", sessions);
        inject(play, "mediaServerService", media);
        inject(play, "zlmApiUtils", api);
        inject(play, "sipDeviceService", devices);

        assertThrows(AccessDeniedException.class, () -> play.closeStream(DEVICE, CHANNEL, "other-stream"));
        assertEquals("", play.closeStream(DEVICE, CHANNEL, STREAM));
        verifyNoInteractions(api, sip);

        MediaServer node = new MediaServer();
        when(sessions.getSessionInfo(DEVICE, CHANNEL, STREAM, "play")).thenReturn(session(NODE, STREAM, "ssrc-1"));
        when(media.selectMediaServerByServerId(NODE)).thenReturn(node);
        JSONObject readers = new JSONObject();
        readers.put("code", 0);
        readers.put("readerCount", 0);
        readers.put("totalReaderCount", 1);
        when(api.getMediaList(node, "rtp", "rtmp", STREAM)).thenReturn(readers);
        play.closeStream(DEVICE, CHANNEL, STREAM);
        verifyNoInteractions(sip);

        readers.put("totalReaderCount", 0);
        SipDevice device = new SipDevice();
        when(devices.selectSipDeviceBySipId(DEVICE)).thenReturn(device);
        play.closeStream(DEVICE, CHANNEL, STREAM);
        verify(sip).streamByeCmd(device, CHANNEL, STREAM, null);
    }

    @Test
    public void secondViewerReusesPendingSipSessionAndExpiredSessionCanRestart() throws Exception {
        PlayServiceImpl play = new PlayServiceImpl();
        ISipCmd sip = mock(ISipCmd.class);
        VideoSessionManager sessions = mock(VideoSessionManager.class);
        IZmlHookService hooks = mock(IZmlHookService.class);
        IMediaServerService media = mock(IMediaServerService.class);
        ZlmApiUtils api = mock(ZlmApiUtils.class);
        ISipDeviceService devices = mock(ISipDeviceService.class);
        inject(play, "sipCmd", sip);
        inject(play, "streamSession", sessions);
        inject(play, "zmlHookService", hooks);
        inject(play, "mediaServerService", media);
        inject(play, "zlmApiUtils", api);
        inject(play, "sipDeviceService", devices);

        SipDevice device = new SipDevice();
        VideoSessionInfo pending = session(NODE, STREAM, "ssrc-1");
        pending.setPushing(false);
        pending.setPort(30000);
        pending.setPlayRequestedAt(System.currentTimeMillis());
        Stream current = new Stream();
        when(devices.selectSipDeviceBySipId(DEVICE)).thenReturn(device);
        when(sessions.getSessionInfo(DEVICE, CHANNEL, STREAM, null)).thenReturn(null, pending);
        when(sip.playStreamCmd(device, CHANNEL, false)).thenReturn(pending);
        when(hooks.updateStream(pending)).thenReturn(current);

        assertSame(current, play.play(DEVICE, CHANNEL, false));
        assertSame(current, play.play(DEVICE, CHANNEL, false));
        verify(sip, times(1)).playStreamCmd(device, CHANNEL, false);
        verifyNoMoreInteractions(sip);
        verifyNoInteractions(api);

        pending.setPlayRequestedAt(0);
        VideoSessionInfo restarted = session(NODE, STREAM, "ssrc-2");
        Stream replacement = new Stream();
        when(sip.playStreamCmd(device, CHANNEL, false)).thenReturn(restarted);
        when(hooks.updateStream(restarted)).thenReturn(replacement);
        assertSame(replacement, play.play(DEVICE, CHANNEL, false));
        verify(sip).streamByeCmd(device, CHANNEL, STREAM, null);
    }

    @Test
    public void playbackRateLimitIsIsolatedByUser() throws Exception {
        Method method = PlayerController.class.getMethod("play", String.class, String.class);
        RateLimiter limiter = method.getAnnotation(RateLimiter.class);
        assertEquals(120, limiter.count());
        assertEquals(60, limiter.time());
        JoinPoint joinPoint = mock(JoinPoint.class);
        MethodSignature signature = mock(MethodSignature.class);
        when(joinPoint.getSignature()).thenReturn(signature);
        when(signature.getMethod()).thenReturn(method);
        RateLimiterAspect aspect = new RateLimiterAspect();

        login(21L, "iot:video:list");
        String firstKey = aspect.getCombineKey(limiter, joinPoint);
        login(22L, "iot:video:list");
        assertNotEquals(firstKey, aspect.getCombineKey(limiter, joinPoint));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void requiresSeparateNodeAndPlaybackTokensBoundToTheLiveSession() throws Exception {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        ValueOperations<String, String> values = mock(ValueOperations.class);
        Map<String, String> cache = new HashMap<>();
        when(redis.opsForValue()).thenReturn(values);
        when(values.get(anyString())).thenAnswer(call -> cache.get(call.getArgument(0)));
        when(values.setIfAbsent(anyString(), anyString())).thenAnswer(call ->
                cache.putIfAbsent(call.getArgument(0), call.getArgument(1)) == null);
        doAnswer(call -> {
            cache.put(call.getArgument(0), call.getArgument(1));
            return null;
        }).when(values).set(anyString(), anyString(), any(Duration.class));

        MediaServerMapper nodes = mock(MediaServerMapper.class);
        MediaServer node = new MediaServer();
        node.setServerId(NODE);
        node.setTenantId(21L);
        when(nodes.selectMediaServerList(argThat(query -> NODE.equals(query.getServerId()))))
                .thenReturn(Collections.singletonList(node));
        MediaAccessTokens tokens = new MediaAccessTokens(redis, nodes);
        String hookToken = tokens.provisionHookToken(node);
        assertEquals(hookToken, tokens.provisionHookToken(node));

        VideoSessionManager sessions = mock(VideoSessionManager.class);
        VideoSessionInfo session = session(NODE, STREAM, "ssrc-1");
        when(sessions.getSessionInfoBySSRC(STREAM)).thenReturn(session);
        String playToken = tokens.issuePlayback(session);
        verify(values).set(anyString(), anyString(), eq(Duration.ofMinutes(5)));
        assertNotEquals(hookToken, playToken);
        String url = tokens.playbackUrl("https://example.invalid/media?option=1", playToken);
        assertTrue(url.endsWith("&playToken=" + playToken));

        ZmlHookServiceImpl hookService = new ZmlHookServiceImpl();
        inject(hookService, "mediaAccessTokens", tokens);
        inject(hookService, "videoSessionManager", sessions);
        ZmlHookController hook = new ZmlHookController();
        inject(hook, "mediaAccessTokens", tokens);
        inject(hook, "zmlHookService", hookService);

        JSONObject body = new JSONObject();
        body.put("mediaServerId", NODE);
        body.put("app", "rtp");
        body.put("vhost", "__defaultVhost__");
        body.put("stream", STREAM);
        assertEquals(HttpStatus.UNAUTHORIZED, hook.onPlay(body, null).getStatusCode());
        assertEquals(HttpStatus.UNAUTHORIZED, hook.onStreamNoneReader(body, playToken).getStatusCode());
        verifyNoInteractions(sessions);
        assertEquals(401, JSONObject.parseObject(hook.onPlay(body, hookToken).getBody()).getIntValue("code"));

        body.put("params", "playToken=" + playToken);
        assertEquals(0, JSONObject.parseObject(hook.onPlay(body, hookToken).getBody()).getIntValue("code"));
        assertEquals(1, session.getOnPlaytime());
        body.put("path", "/rtp/" + STREAM + "/segment.ts");
        assertEquals("", JSONObject.parseObject(hook.onHttpAccess(body, hookToken).getBody()).getString("err"));
        body.remove("params");
        assertEquals("Unauthorized", JSONObject.parseObject(hook.onHttpAccess(body, hookToken).getBody()).getString("err"));
        body.put("path", "/logo.png");
        assertEquals("", JSONObject.parseObject(hook.onHttpAccess(body, hookToken).getBody()).getString("err"));
        body.put("params", "playToken=" + playToken);
        body.put("app", "another-app");
        assertEquals(401, JSONObject.parseObject(hook.onPlay(body, hookToken).getBody()).getIntValue("code"));
        body.put("app", "rtp");
        when(sessions.getSessionInfoBySSRC(STREAM)).thenReturn(session(NODE, STREAM, "ssrc-2"));
        assertEquals(401, JSONObject.parseObject(hook.onPlay(body, hookToken).getBody()).getIntValue("code"));
        when(sessions.getSessionInfoBySSRC(STREAM)).thenReturn(session);
        cache.values().removeIf(value -> value.startsWith(NODE + "/"));
        assertEquals(401, JSONObject.parseObject(hook.onPlay(body, hookToken).getBody()).getIntValue("code"));
    }

    private static VideoSessionInfo session(String node, String stream, String ssrc) {
        return VideoSessionInfo.builder().mediaServerId(node).deviceId(DEVICE).channelId(CHANNEL)
                .stream(stream).ssrc(ssrc).pushing(true).build();
    }

    private static void login(Long userId, String permission) {
        LoginUser principal = new LoginUser(userId, null, new SysUser(userId), Collections.singleton(permission));
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(principal, null, Collections.emptyList()));
    }

    private static void inject(Object target, String name, Object value) throws ReflectiveOperationException {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }

    @Configuration
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    public static class PlayerTestConfig {
        @Bean("ss")
        public PermissionService permissionService() {
            return new PermissionService();
        }

        @Bean
        public PlayerController playerController() {
            return new PlayerController();
        }

        @Bean
        public SipDeviceChannelMapper channels() {
            return mock(SipDeviceChannelMapper.class);
        }

        @Bean
        public IPlayService playService() {
            return mock(IPlayService.class);
        }

    }
}
