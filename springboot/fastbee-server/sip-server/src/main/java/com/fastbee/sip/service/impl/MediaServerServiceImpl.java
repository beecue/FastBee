package com.fastbee.sip.service.impl;

import com.alibaba.fastjson.JSONObject;
import com.fastbee.common.core.domain.entity.SysUser;
import com.fastbee.common.exception.ServiceException;
import com.fastbee.common.utils.DateUtils;
import com.fastbee.common.utils.MessageUtils;
import com.fastbee.iot.domain.Device;
import com.fastbee.iot.mapper.DeviceMapper;
import com.fastbee.sip.conf.SysSipConfig;
import com.fastbee.sip.domain.MediaServer;
import com.fastbee.sip.domain.SipConfig;
import com.fastbee.sip.domain.SipDevice;
import com.fastbee.sip.mapper.MediaServerMapper;
import com.fastbee.sip.model.VideoSessionInfo;
import com.fastbee.sip.model.ZlmMediaServer;
import com.fastbee.sip.server.VideoSessionManager;
import com.fastbee.sip.service.IMediaServerService;
import com.fastbee.sip.service.MediaAccessTokens;
import com.fastbee.sip.util.ZlmApiUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

import java.util.*;

import static com.fastbee.common.utils.SecurityUtils.getLoginUser;
import static com.fastbee.common.utils.SecurityUtils.isAdmin;

/**
 * 流媒体服务器配置Service业务层处理
 *
 * @author zhuangpeng.li
 * @date 2022-11-30
 */
@Slf4j
@Service
public class MediaServerServiceImpl implements IMediaServerService {
    @Autowired
    private MediaServerMapper mediaServerMapper;
    @Autowired
    private DeviceMapper deviceMapper;

    @Autowired
    private ZlmApiUtils zlmApiUtils;

    @Autowired
    private VideoSessionManager streamSession;

    @Autowired
    private MediaAccessTokens mediaAccessTokens;

    @Autowired
    private SysSipConfig sipConfig;

    @Override
    public MediaServer selectMediaServerById(Long id) {
        return mediaServerMapper.selectMediaServerById(id);
    }

    @Override
    public MediaServer selectMediaServerByServerId(String serverId) {
        if (serverId == null || serverId.isEmpty()) {
            return null;
        }
        MediaServer query = new MediaServer();
        query.setServerId(serverId);
        List<MediaServer> nodes = mediaServerMapper.selectMediaServerList(query);
        return nodes.size() == 1 && serverId.equals(nodes.get(0).getServerId()) ? nodes.get(0) : null;
    }

    /**
     * 查询流媒体服务器配置
     *
     * @return 流媒体服务器配置
     */
    @Override
    public List<MediaServer> selectMediaServer() {
        MediaServer mediaServer = new MediaServer();
        SysUser user = getLoginUser().getUser();
        if (!user.isAdmin()) {
            mediaServer.setTenantId(user.getUserId());
        }
        return mediaServerMapper.selectMediaServer(mediaServer);
    }

    @Override
    public MediaServer selectMediaServerBytenantId(Long tenantId) {
        List<MediaServer> list = mediaServerMapper.selectMediaServerBytenantId(tenantId);
        if (list.size() == 0) {
            return Long.valueOf(1L).equals(tenantId) ? null : selectMediaServerBytenantId(1L);
        } else if (list.size() == 1) {
            return list.get(0);
        } else {
            //随机选择一个流媒体节点
            Random random = new Random();
            int index = random.nextInt(list.size());
            return list.get(index);
        }
    }

    @Override
    public MediaServer selectMediaServerBydeviceSipId(String deviceSipId) {
        Device device = deviceMapper.selectDeviceBySerialNumber(deviceSipId);
        if (device != null) {
            List<MediaServer> list = mediaServerMapper.selectMediaServerBytenantId(device.getTenantId());
            if (list.size() == 0) {
                return selectMediaServerBytenantId(1L);
            } else if (list.size() == 1) {
                return list.get(0);
            } else {
                //随机选择一个流媒体节点
                Random random = new Random();
                int index = random.nextInt(list.size());
                return list.get(index);
            }
        } else {
            return selectMediaServerBytenantId(1L);
        }

    }

    /**
     * 查询流媒体服务器配置列表
     *
     * @param mediaServer 流媒体服务器配置
     * @return 流媒体服务器配置
     */
    @Override
    public List<MediaServer> selectMediaServerList(MediaServer mediaServer) {
        SysUser user = getLoginUser().getUser();
//        List<SysRole> roles=user.getRoles();
//        // 租户
//        if(roles.stream().anyMatch(a->a.getRoleKey().equals("tenant"))){
//            mediaServer.setTenantId(user.getUserId());
//        }
        mediaServer.setTenantId(user.getUserId());
        return mediaServerMapper.selectMediaServerList(mediaServer);
    }

    /**
     * 新增流媒体服务器配置
     *
     * @param mediaServer 流媒体服务器配置
     * @return 结果
     */
    @Override
    public int insertMediaServer(MediaServer mediaServer) {
        // 判断是否为管理员
        mediaServer.setIsSys(1);
        SysUser user = getLoginUser().getUser();
//        List<SysRole> roles=user.getRoles();
//        for(int i=0;i<roles.size();i++){
//            if(roles.get(i).getRoleKey().equals("tenant") || roles.get(i).getRoleKey().equals("general")){
//                mediaServer.setIsSys(0);
//                break;
//            }
//        }
        if (null == user.getDeptId()) {
            throw new ServiceException(MessageUtils.message("only.allow.tenant.config"));
        }
        if (!isAdmin(user.getUserId())) {
            mediaServer.setIsSys(0);
        }
        mediaServer.setTenantId(user.getUserId());
        mediaServer.setTenantName(user.getUserName());
        //判断相同ip服务器是否存在
        MediaServer temp = new MediaServer();
        temp.setIp(mediaServer.getIp());
        List<MediaServer> list = mediaServerMapper.selectMediaServerList(temp);
        if (list.size() > 0) {
            return 0;
        }
        mediaServer.setCreateTime(DateUtils.getNowDate());
        boolean ret = syncMediaServer(mediaServer, mediaServer.getSecret());
        if (ret) {
            return mediaServerMapper.insertMediaServer(mediaServer);
        } else {
            return 0;
        }
    }

    /**
     * 修改流媒体服务器配置
     *
     * @param mediaServer 流媒体服务器配置
     * @return 结果
     */
    @Override
    public int updateMediaServer(MediaServer mediaServer) {
        if (mediaServer.getId() != null) {
            MediaServer current = requireMediaServerAccess(mediaServer.getId());
            String newSecret = mediaServer.getSecret();
            mediaServer.setTenantId(current.getTenantId());
            mediaServer.setTenantName(current.getTenantName());
            mediaServer.setSecret(current.getSecret());
            boolean ret = syncMediaServer(mediaServer, newSecret);
            if (ret) {
                mediaServer.setSecret(newSecret);
                mediaServer.setUpdateTime(DateUtils.getNowDate());
                return mediaServerMapper.updateMediaServer(mediaServer);
            }
        }
        return 0;
    }

    @Override
    public boolean syncMediaServer(MediaServer mediaServer, String secret) {
        requireUniqueServerId(mediaServer);
        Map<String, Object> param = mediaHookConfig(mediaServer);
        param.put("api.secret", secret);
        param.put("general.flowThreshold", "64");
        param.put("hook.on_record_ts", "");
        param.put("hook.on_shell_login", "");
        param.put("hook.timeoutSec", "20");
        param.put("hook.alive_interval", "60.0");

        param.put("rtsp.port", mediaServer.getPortRtsp().toString());
        param.put("rtmp.port", mediaServer.getPortRtmp().toString());

        param.put("record.appName", "record");
        param.put("record.filePath", "./record");
        if (!ObjectUtils.isEmpty(mediaServer.getRtpPortRange())) {
            param.put("rtp_proxy.port_range", mediaServer.getRtpPortRange().replace(",", "-"));
            log.warn("[ZLM] 修改RTP推流端口时，请同步Docker端口映射");
        }
        JSONObject responseJSON = zlmApiUtils.setServerConfig(mediaServer, param);
        if (responseJSON != null && Integer.valueOf(0).equals(responseJSON.getInteger("code"))) {
            log.info("[ZLM] 设置成功,开始重启以保证配置生效");
            MediaServer restartTarget = new MediaServer();
            restartTarget.setIp(mediaServer.getIp());
            restartTarget.setPortHttp(mediaServer.getPortHttp());
            restartTarget.setSecret(secret);
            zlmApiUtils.restartServer(restartTarget);
            return true;
        }
        log.warn("[ZLM] 设置失败 mediaServerId={}", mediaServer.getServerId());
        return false;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void syncMediaHookSecurity() {
        if (!sipConfig.isEnabled()) {
            return;
        }
        for (MediaServer node : mediaServerMapper.selectMediaServerList(new MediaServer())) {
            try {
                requireUniqueServerId(node);
                JSONObject result = zlmApiUtils.setServerConfig(node, mediaHookConfig(node));
                if (result != null && Integer.valueOf(0).equals(result.getInteger("code"))) {
                    log.info("[ZLM] 回调配置同步成功 mediaServerId={}", node.getServerId());
                    continue;
                }
            } catch (RuntimeException e) {
                log.warn("[ZLM] 回调配置同步异常 mediaServerId={}, error={}", node.getServerId(), e.getClass().getSimpleName());
                continue;
            }
            log.warn("[ZLM] 回调配置同步失败，请检查节点并重新保存流媒体配置 mediaServerId={}", node.getServerId());
        }
    }

    private Map<String, Object> mediaHookConfig(MediaServer mediaServer) {
        String hookPrex = String.format("http://%s/zlmhook", mediaServer.getHookurl());
        Map<String, Object> param = new HashMap<>();
        String token = mediaAccessTokens.provisionHookToken(mediaServer);
        String hookQuery = "?hookToken=" + token;

        param.put("hook.enable", "1");
        // Older ZLM versions support an admin query string that skips playback hooks.
        param.put("hook.admin_params", "fastbeeInternal=" + UUID.randomUUID());
        param.put("api.apiDebug", "0");
        param.put("general.mediaServerId", mediaServer.getServerId());
        for (String event : Arrays.asList("on_play", "on_http_access", "on_publish", "on_server_started",
                "on_stream_changed", "on_stream_none_reader", "on_stream_not_found", "on_send_rtp_stopped",
                "on_rtp_server_timeout", "on_flow_report", "on_server_keepalive", "on_server_exited")) {
            param.put("hook." + event, hookPrex + "/" + event + hookQuery);
        }
        if (Objects.equals(mediaServer.getProtocol(), "http")) {
            param.put("hook.on_record_mp4", String.format("http://127.0.0.1:%s/zlmhook/on_record_mp4%s", mediaServer.getRecordPort(), hookQuery));
        } else if (Objects.equals(mediaServer.getProtocol(), "https")) {
            param.put("hook.on_record_mp4", String.format("https://%s:%s/zlmhook/on_record_mp4%s", mediaServer.getDomain(), mediaServer.getRecordPort(), hookQuery));
        }
        param.put("hook.on_rtsp_auth", "");
        param.put("hook.on_rtsp_realm", "");

        return param;
    }

    private void requireUniqueServerId(MediaServer node) {
        if (node.getServerId() == null || node.getServerId().trim().isEmpty() || node.getServerId().length() > 128) {
            throw new ServiceException("流媒体服务器编号无效");
        }
        MediaServer query = new MediaServer();
        query.setServerId(node.getServerId());
        boolean duplicate = mediaServerMapper.selectMediaServerList(query).stream()
                .anyMatch(existing -> !Objects.equals(existing.getId(), node.getId()));
        if (duplicate) {
            throw new ServiceException("流媒体服务器编号重复");
        }
    }

    /**
     * 批量删除流媒体服务器配置
     *
     * @param ids 需要删除的流媒体服务器配置主键
     * @return 结果
     */
    @Override
    public int deleteMediaServerByIds(Long[] ids) {
        for (Long id : ids) {
            requireMediaServerAccess(id);
        }
        return mediaServerMapper.deleteMediaServerByIds(ids);
    }

    /**
     * 删除流媒体服务器配置信息
     *
     * @param id 流媒体服务器配置主键
     * @return 结果
     */
    @Override
    public int deleteMediaServerById(Long id) {
        requireMediaServerAccess(id);
        return mediaServerMapper.deleteMediaServerById(id);
    }

    private MediaServer requireMediaServerAccess(Long id) {
        SysUser user = getLoginUser().getUser();
        MediaServer node = mediaServerMapper.selectMediaServerById(id);
        if (node == null || (!user.isAdmin() && !Objects.equals(user.getUserId(), node.getTenantId()))) {
            throw new AccessDeniedException("无权管理该流媒体服务器");
        }
        return node;
    }

    @Override
    public JSONObject getMediaList(String schema, String stream) {
        SysUser user = getLoginUser().getUser();
        MediaServer media = selectMediaServerBytenantId(user.getUserId());
        if (media != null) {
            return zlmApiUtils.getMediaList(media, "live", schema, stream).getJSONObject("data");
        }
        return null;
    }

    @Override
    public JSONObject listRtpServer() {
        SysUser user = getLoginUser().getUser();
        MediaServer media = selectMediaServerBytenantId(user.getUserId());
        if (media != null) {
            return zlmApiUtils.listRtpServer(media).getJSONObject("data");
        }
        return null;
    }

    @Override
    public VideoSessionInfo createRTPServer(SipConfig sipConfig, MediaServer mediaInfo, SipDevice device, VideoSessionInfo videoSessionInfo) {
        switch (videoSessionInfo.getType()) {
            case play:
                videoSessionInfo.setSsrc(streamSession.createPlaySsrc(sipConfig.getDomain()));
                videoSessionInfo.setStream(String.format("gb_play_%s_%s", device.getDeviceSipId(), videoSessionInfo.getChannelId()));
                break;
            case playrecord:
                videoSessionInfo.setSsrc(streamSession.createPlaySsrc(sipConfig.getDomain()));
                videoSessionInfo.setStream(String.format("gb_playrecord_%s_%s", device.getDeviceSipId(), videoSessionInfo.getChannelId()));
                break;
            case playback:
                videoSessionInfo.setSsrc(streamSession.createPlayBackSsrc(sipConfig.getDomain()));
                videoSessionInfo.setStream(videoSessionInfo.getSsrc());
                break;
            case download:
                videoSessionInfo.setSsrc(streamSession.createPlayBackSsrc(sipConfig.getDomain()));
                videoSessionInfo.setStream(videoSessionInfo.getSsrc());
                break;
        }

        int mediaPort = zlmApiUtils.createRTPServer(mediaInfo, videoSessionInfo.getStream(), videoSessionInfo.getSsrc(), false, false, 0);
        videoSessionInfo.setPort(mediaPort);
        return videoSessionInfo;
    }

    @Override
    public MediaServer checkMediaServer(String ip, Long port, String secret) {
        MediaServer mediaServerItem = new MediaServer();
        mediaServerItem.setIp(ip);
        mediaServerItem.setPortHttp(port);
        mediaServerItem.setSecret(secret);
        ZlmMediaServer zlmServerConfig = zlmApiUtils.getMediaServerConfig(mediaServerItem);
        if (zlmServerConfig == null) {
            return null;
        }
        mediaServerItem.setServerId(zlmServerConfig.getMediaServerId());
        mediaServerItem.setPortRtmp(Long.valueOf(zlmServerConfig.getRtmpPort()));
        mediaServerItem.setPortRtsp(Long.valueOf(zlmServerConfig.getRtspPort()));
        mediaServerItem.setRtpProxyPort(Long.valueOf(zlmServerConfig.getRtpProxyPort()));
        mediaServerItem.setHookurl("java:8080");
        return mediaServerItem;
    }
}
