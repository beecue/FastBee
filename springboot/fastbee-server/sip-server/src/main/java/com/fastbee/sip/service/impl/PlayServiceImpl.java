package com.fastbee.sip.service.impl;

import com.alibaba.fastjson.JSONObject;
import com.google.common.util.concurrent.Striped;
import com.fastbee.sip.domain.MediaServer;
import com.fastbee.sip.domain.SipDevice;
import com.fastbee.sip.model.Stream;
import com.fastbee.sip.model.VideoSessionInfo;
import com.fastbee.sip.server.ISipCmd;
import com.fastbee.sip.server.VideoSessionManager;
import com.fastbee.sip.service.*;
import com.fastbee.sip.util.ZlmApiUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;

@Service
@Slf4j
public class PlayServiceImpl implements IPlayService {
    private static final long STREAM_START_TIMEOUT = TimeUnit.SECONDS.toMillis(15);
    private final Striped<Lock> streamLocks = Striped.lazyWeakLock(1024);

    @Autowired
    private ISipCmd sipCmd;

    @Autowired
    private IZmlHookService zmlHookService;

    @Autowired
    private VideoSessionManager streamSession;

    @Autowired
    private ISipDeviceService sipDeviceService;

    @Autowired
    private IMediaServerService mediaServerService;

    @Autowired
    private ZlmApiUtils zlmApiUtils;

    @Override
    public Stream play(String deviceId, String channelId, boolean record) {
        SipDevice dev = sipDeviceService.selectSipDeviceBySipId(deviceId);
        if (dev == null) {
            log.error("play dev is null,deviceId:{},channelId:{}", deviceId, channelId);
            return null;
        }
        String streamId = String.format(record ? "gb_playrecord_%s_%s" : "gb_play_%s_%s", deviceId, channelId);
        Lock lock = streamLocks.get(streamId);
        lock.lock();
        try {
            VideoSessionInfo session = streamSession.getSessionInfo(deviceId, channelId, streamId, null);
            if (session != null) {
                boolean active = record ? session.isRecording() : session.isPushing();
                long waiting = System.currentTimeMillis() - session.getPlayRequestedAt();
                if (!active && session.getPort() > 0 && waiting >= 0 && waiting < STREAM_START_TIMEOUT) {
                    return zmlHookService.updateStream(session);
                }
                MediaServer media = mediaServerService.selectMediaServerByServerId(session.getMediaServerId());
                JSONObject rtpInfo = zlmApiUtils.getRtpInfo(media, streamId);
                if (active && rtpInfo != null && Integer.valueOf(0).equals(rtpInfo.getInteger("code"))
                        && rtpInfo.getBooleanValue("exist") && rtpInfo.getIntValue("local_port") > 0) {
                    return zmlHookService.updateStream(session);
                }
                sipCmd.streamByeCmd(dev, channelId, streamId, null);
            }
            return zmlHookService.updateStream(sipCmd.playStreamCmd(dev, channelId, record));
        } finally {
            lock.unlock();
        }
    }

    @Override
    public String closeStream(String deviceId, String channelId, String streamId) {
        if (!Objects.equals(String.format("gb_play_%s_%s", deviceId, channelId), streamId)) {
            throw new AccessDeniedException("视频流与设备通道不匹配");
        }
        VideoSessionInfo session = streamSession.getSessionInfo(deviceId, channelId, streamId, "play");
        if (session == null || !Objects.equals(deviceId, session.getDeviceId())
                || !Objects.equals(channelId, session.getChannelId()) || !Objects.equals(streamId, session.getStream())) {
            return "";
        }
        MediaServer mediaInfo = mediaServerService.selectMediaServerByServerId(session.getMediaServerId());
        if (mediaInfo == null) {
            return "";
        }
        JSONObject ret = zlmApiUtils.getMediaList(mediaInfo, "rtp", "rtmp", streamId);
        // A close request may arrive while another player is the only remaining reader.
        if (ret != null && Integer.valueOf(0).equals(ret.getInteger("code"))
                && Integer.valueOf(0).equals(ret.getInteger("totalReaderCount"))) {
            SipDevice dev = sipDeviceService.selectSipDeviceBySipId(deviceId);
            if (dev != null) {
                sipCmd.streamByeCmd(dev, channelId, streamId, null);
            }
        }
        return "";
    }
}
