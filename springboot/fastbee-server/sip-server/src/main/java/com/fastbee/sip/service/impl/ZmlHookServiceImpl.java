package com.fastbee.sip.service.impl;

import com.alibaba.fastjson.JSONObject;
import com.fastbee.sip.domain.MediaServer;
import com.fastbee.sip.enums.SessionType;
import com.fastbee.sip.model.Stream;
import com.fastbee.sip.model.VideoSessionInfo;
import com.fastbee.sip.server.ISipCmd;
import com.fastbee.sip.server.VideoSessionManager;
import com.fastbee.sip.service.IMediaServerService;
import com.fastbee.sip.service.IZmlHookService;
import com.fastbee.sip.service.MediaAccessTokens;
import com.fastbee.sip.util.ZlmApiUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Slf4j
@Service
public class ZmlHookServiceImpl implements IZmlHookService {

    @Autowired
    private VideoSessionManager videoSessionManager;

    @Autowired
    private IMediaServerService mediaServerService;

    @Autowired
    private ISipCmd sipCmd;

    @Autowired
    private ZlmApiUtils zlmApiUtils;

    @Autowired
    private MediaAccessTokens mediaAccessTokens;

    @Override
    public JSONObject onHttpAccess(JSONObject json) {
        JSONObject ret = new JSONObject();
        ret.put("code", 0);
        ret.put("path", "");
        ret.put("second", 0);
        String path = json.getString("path");
        String error = "";
        if (path == null || path.contains("\\") || path.contains("//") || path.contains("/./")
                || path.contains("/../") || path.endsWith("/.") || path.endsWith("/..")
                || "/rtp".equals(path) || "/rtp/".equals(path)) {
            error = "Unauthorized";
        } else if (path.startsWith("/rtp/")) {
            String[] parts = path.split("/", 4);
            VideoSessionInfo session = parts.length == 4
                    ? findSession(json.getString("mediaServerId"), parts[2]) : null;
            if (!mediaAccessTokens.allowsPlayback(json.getString("params"), session)) {
                error = "Unauthorized";
            }
        }
        ret.put("err", error);
        return ret;
    }

    @Override
    public JSONObject onPlay(JSONObject json) {
        String mediaServerId = json.getString("mediaServerId");
        String id = json.getString("id");
        String schema = json.getString("schema");
        String app = json.getString("app");
        String streamId = json.getString("stream");
        VideoSessionInfo sinfo = findRtpSession(json);
        JSONObject ret = new JSONObject();
        if (!mediaAccessTokens.allowsPlayback(json.getString("params"), sinfo)) {
            log.warn("[ZLM HOOK] 播放鉴权拒绝 mediaServerId={}, app={}, stream={}", mediaServerId, app, streamId);
            ret.put("code", 401);
            ret.put("msg", "Unauthorized");
            return ret;
        }
        log.debug("[ZLM HOOK] 播放鉴权通过, {} {}->{}->{}/{}", mediaServerId, id, schema, app, streamId);
        ret.put("code", 0);
        ret.put("msg", "success");
        if (sinfo.isPushing()) {
            sinfo.setOnPlaytime(sinfo.getOnPlaytime() + 1);
            videoSessionManager.put(sinfo, null);
        }
        return ret;
    }

    private VideoSessionInfo findRtpSession(JSONObject json) {
        if (!"rtp".equals(json.getString("app")) || !"__defaultVhost__".equals(json.getString("vhost"))) {
            return null;
        }
        return findSession(json.getString("mediaServerId"), json.getString("stream"));
    }

    private VideoSessionInfo findSession(String mediaServerId, String streamId) {
        if (mediaServerId == null || streamId == null || !streamId.matches("[a-zA-Z0-9_-]{1,256}")) {
            return null;
        }
        VideoSessionInfo session = videoSessionManager.getSessionInfoBySSRC(streamId);
        return session != null && streamId.equals(session.getStream()) && mediaServerId.equals(session.getMediaServerId())
                ? session : null;
    }

    @Override
    public JSONObject onPublish(JSONObject json) {
        String id = json.getString("id");
        String mediaServerId = json.getString("mediaServerId");
        String schema = json.getString("schema");
        String app = json.getString("app");
        String streamId = json.getString("stream");
        JSONObject ret = new JSONObject();
        VideoSessionInfo sinfo = findRtpSession(json);
        if (sinfo != null) {
            log.warn("[ZLM HOOK] 推流鉴权, {}->{}->{}/{}", mediaServerId, schema, app, streamId);
            ret.put("code", 0);
            ret.put("msg", "success");
            switch (sinfo.getType()) {
                case play:
                    ret.put("enable_fmp4", true);
                    ret.put("enable_hls", true);
                    ret.put("enable_rtmp", true);
                    ret.put("enable_rtsp", true);
                    break;
                case playrecord:
                    ret.put("enable_rtmp", true);
                    ret.put("enable_hls", true);
                    ret.put("enable_mp4", true);
                    ret.put("enable_audio", true);
                    ret.put("mp4_max_second", 30);
                    ret.put("mp4_as_player", true);
                    ret.put("mp4_save_path", "/opt/media/bin/www");
                    sinfo.setRecording(true);
                    break;
                case playback:
                    ret.put("enable_fmp4", true);
                    ret.put("enable_hls", true);
                    ret.put("enable_rtmp", true);
                    break;
                case download:
                    //开启录像，默认60s
                    ret.put("enable_mp4", true);
                    ret.put("enable_audio", true);
                    ret.put("mp4_max_second", 30);
                    ret.put("mp4_save_path", "/opt/media/bin/www");
                    break;
            }
            sinfo.setPushing(true);
            videoSessionManager.put(sinfo, null);
        } else {
            log.warn("[ZLM HOOK] 推流鉴权失败, {}->{}->{}/{}", mediaServerId, schema, app, streamId);
            ret.put("code", 401);
            ret.put("msg", "Unauthorized");
        }
        return ret;
    }

    @Override
    public JSONObject onStreamNoneReader(JSONObject json) {
        String mediaServerId = json.getString("mediaServerId");
        String schema = json.getString("schema");
        String app = json.getString("app");
        String streamId = json.getString("stream");
        log.warn("[ZLM HOOK] 流无人观看, {}->{}->{}/{}", mediaServerId, schema, app, streamId);
        JSONObject ret = new JSONObject();
        VideoSessionInfo sinfo = findRtpSession(json);
        if (sinfo != null) {
            ret.put("code", 0);
            switch (sinfo.getType()) {
                case playrecord:
                case download:
                    ret.put("close", false);
                    break;
                default:
                    ret.put("close", true);
            }
        }
        return ret;
    }

    @Override
    public JSONObject onStreamNotFound(JSONObject json) {
        String id = json.getString("id");
        String mediaServerId = json.getString("mediaServerId");
        String schema = json.getString("schema");
        String app = json.getString("app");
        String streamId = json.getString("stream");
        log.warn("[ZLM HOOK] 流未找到, {} {}->{}->{}/{}", mediaServerId, id, schema, app, streamId);
        JSONObject ret = new JSONObject();
        ret.put("code", 0);
        ret.put("msg", "success");
        return ret;
    }

    @Override
    public JSONObject onStreamChanged(JSONObject json) {
        boolean regist = json.getBoolean("regist");
        String mediaServerId = json.getString("mediaServerId");
        String schema = json.getString("schema");
        String app = json.getString("app");
        String streamId = json.getString("stream");
        VideoSessionInfo sinfo = findRtpSession(json);
        if (sinfo != null) {
            if (regist) {
                log.info("[ZLM HOOK] 流注册, {}->{}->{}/{}", mediaServerId, schema, app, streamId);
                if (schema.equals("rtsp") && sinfo.getType() == SessionType.play) {
                    MediaServer mediaInfo = mediaServerService.selectMediaServerByServerId(sinfo.getMediaServerId());
                    if (mediaInfo != null) {
                        String streamUrl = String.format("rtsp://127.0.0.1:%s/rtp/%s", mediaInfo.getPortRtsp(), sinfo.getStream());
                        String fileName = sinfo.getDeviceId() + "_" + sinfo.getChannelId() + ".jpg";
                        zlmApiUtils.getSnap(mediaInfo, mediaAccessTokens.playbackUrl(streamUrl,
                                mediaAccessTokens.issuePlayback(sinfo)), 15, 1, fileName);
                    }
                }
                sinfo.setPushing(true);
            } else {
                log.info("[ZLM HOOK] 流注销, {}->{}->{}/{}", mediaServerId, schema, app, streamId);
                if (sinfo != null ) {
                    if (sinfo.isPushing()) {
                        sinfo.setPushing(false);
                    }
                    if(sinfo.isRecording()) {
                        sinfo.setRecording(false);
                    }
                }
            }
            videoSessionManager.put(sinfo, null);
        }
        JSONObject ret = new JSONObject();
        ret.put("code", 0);
        ret.put("msg", "success");
        return ret;
    }

    @Override
    public JSONObject onFlowReport(JSONObject json) {
        String id = json.getString("id");
        String mediaServerId = json.getString("mediaServerId");
        String schema = json.getString("schema");
        String app = json.getString("app");
        String streamId = json.getString("stream");
        int duration = json.getInteger("duration");
        int totalBytes = json.getInteger("totalBytes");
        boolean player = json.getBoolean("player");
        VideoSessionInfo sinfo = findRtpSession(json);
        if (sinfo != null) {
            if (player) {
                int time = sinfo.getOnPlaytime() - 1;
                sinfo.setOnPlaytime(time);
                log.info("[ZLM HOOK] 播放器断开，流量统计事件, {}->{}->{}/{}", mediaServerId, schema, app, streamId);
            } else {
                log.info("[ZLM HOOK] 推流器断开，流量统计事件, {}->{}->{}/{}", mediaServerId, schema, app, streamId);
                sinfo.setPushing(false);
                sinfo.setPlayer(0);
                sinfo.setOnPlaytime(0);
            }
            videoSessionManager.put(sinfo, null);
        }
        log.info("[ZLM HOOK] onFlowReport：维持时间：{}/上下行流量：{}", duration, totalBytes);
        JSONObject ret = new JSONObject();
        ret.put("code", 0);
        ret.put("msg", "success");
        return ret;
    }


    @Override
    public JSONObject onRtpServerTimeout(JSONObject json) {
        String mediaServerId = json.getString("mediaServerId");
        String stream_id = json.getString("stream_id");
        String ssrc = json.getString("ssrc");
        log.warn("[ZLM HOOK] rtpServer收流超时：{}->{}({})", mediaServerId, stream_id, ssrc);
        JSONObject ret = new JSONObject();
        ret.put("code", 0);
        ret.put("msg", "success");
        return ret;
    }

    @Override
    public JSONObject onSendRtpStopped(JSONObject json) {
        log.warn("[ZLM HOOK] rtp发送停止回调：{}", json);
        String mediaServerId = json.getString("mediaServerId");
        String stream_id = json.getString("stream_id");
        String ssrc = json.getString("ssrc");
        log.warn("[ZLM HOOK] rtp发送停止回调：{}->{}({})", mediaServerId, stream_id, ssrc);
        JSONObject ret = new JSONObject();
        ret.put("code", 0);
        ret.put("msg", "success");
        return ret;
    }

    @Override
    public JSONObject onRecordMp4(JSONObject json) {
        String mediaServerId = json.getString("mediaServerId");
        String file_path = json.getString("file_path");
        String app = json.getString("app");
        String stream = json.getString("stream");
        log.info("[ZLM HOOK] 录制完成：{}->{} {} ({})", mediaServerId, app, stream, file_path);
        JSONObject ret = new JSONObject();
        ret.put("code", 0);
        ret.put("msg", "success");
        return ret;
    }

    @Override
    public JSONObject onServerStarted(JSONObject json) {
        log.info("[ZLM HOOK] 流媒体服务启动成功 mediaServerId={}", json.getString("mediaServerId"));
        JSONObject ret = new JSONObject();
        ret.put("code", 0);
        ret.put("msg", "success");
        return ret;
    }

    @Override
    public JSONObject onServerKeepalive(JSONObject json) {
        log.debug("[ZLM HOOK] 流媒体服务心跳 mediaServerId={}", json.getString("mediaServerId"));
        JSONObject ret = new JSONObject();
        ret.put("code", 0);
        ret.put("msg", "success");
        return ret;
    }

    @Override
    public JSONObject onServerExited(JSONObject json) {
        log.info("[ZLM HOOK] 流媒体服务退出 mediaServerId={}", json.getString("mediaServerId"));
        JSONObject ret = new JSONObject();
        ret.put("code", 0);
        ret.put("msg", "success");
        return ret;
    }

    public Stream updateStream(VideoSessionInfo sInfo) {
        if(sInfo == null){
            log.error("updateStream sInfo is null");
            return null;
        }
        String streamId = sInfo.getStream();
        String ssrc = sInfo.getSsrc();
        MediaServer mediaInfo = mediaServerService.selectMediaServerByServerId(sInfo.getMediaServerId());
        if (mediaInfo == null) {
            return null;
        }
        Stream streamUrl = new Stream(sInfo.getDeviceId(), sInfo.getChannelId(), streamId, ssrc);
        String token = mediaAccessTokens.issuePlayback(sInfo);
        String server = Objects.equals(mediaInfo.getDomain(), "") ? mediaInfo.getIp() : mediaInfo.getDomain();
        String http = String.format("http://%s:%s/rtp/%s", mediaInfo.getIp(), mediaInfo.getPortHttp(), streamId);
        String https = String.format("https://%s:%s/rtp/%s", mediaInfo.getIp(), mediaInfo.getPortHttps(), streamId);
        streamUrl.setFlv(mediaAccessTokens.playbackUrl(http + ".live.flv", token));
        streamUrl.setHttps_flv(mediaAccessTokens.playbackUrl(String.format("https://%s:%s/rtp/%s.live.flv",
                server, mediaInfo.getPortHttps(), streamId), token));
        streamUrl.setWs_flv(mediaAccessTokens.playbackUrl(String.format("ws://%s:%s/rtp/%s.live.flv",
                mediaInfo.getIp(), mediaInfo.getPortHttps(), streamId), token));
        streamUrl.setRtmp(mediaAccessTokens.playbackUrl(String.format("rtmp://%s:%s/rtp/%s",
                mediaInfo.getIp(), mediaInfo.getPortRtmp(), streamId), token));
        streamUrl.setRtsp(mediaAccessTokens.playbackUrl(String.format("rtsp://%s:%s/rtp/%s",
                mediaInfo.getIp(), mediaInfo.getPortRtsp(), streamId), token));
        streamUrl.setFmp4(mediaAccessTokens.playbackUrl(http + ".live.mp4", token));
        streamUrl.setHttps_fmp4(mediaAccessTokens.playbackUrl(https + ".live.mp4", token));
        streamUrl.setHls(mediaAccessTokens.playbackUrl(http + "/hls.m3u8", token));
        streamUrl.setHttps_hls(mediaAccessTokens.playbackUrl(String.format("https://%s:%s/rtp/%s/hls.m3u8",
                mediaInfo.getIp(), mediaInfo.getPortHttp(), streamId), token));

        if (Objects.equals(mediaInfo.getProtocol(), "http")) {
            streamUrl.setPlayurl(streamUrl.getFlv());
        } else if (Objects.equals(mediaInfo.getProtocol(), "https")) {
            streamUrl.setPlayurl(streamUrl.getHttps_flv());
        } else if (Objects.equals(mediaInfo.getProtocol(), "ws")) {
            streamUrl.setPlayurl(streamUrl.getWs_flv());
        } else if (Objects.equals(mediaInfo.getProtocol(), "rtmp")) {
            streamUrl.setPlayurl(streamUrl.getRtmp());
        } else if (Objects.equals(mediaInfo.getProtocol(), "rtsp")) {
            streamUrl.setPlayurl(streamUrl.getRtsp());
        }

        return streamUrl;
    }
}
