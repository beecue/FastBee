package com.fastbee.data.controller.media;

import com.fastbee.common.annotation.RateLimiter;
import com.fastbee.common.core.domain.AjaxResult;
import com.fastbee.common.enums.LimitType;
import com.fastbee.common.utils.SecurityUtils;
import com.fastbee.sip.domain.SipDeviceChannel;
import com.fastbee.sip.mapper.SipDeviceChannelMapper;
import com.fastbee.sip.model.Stream;
import com.fastbee.sip.service.IPlayService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Objects;

@Slf4j
@Api(tags = "播放器")
@RestController
@RequestMapping("/sip/player")
@PreAuthorize("@ss.hasPermi('iot:video:list')")
public class PlayerController {
    @Autowired
    private IPlayService playService;

    @Autowired
    private SipDeviceChannelMapper channelMapper;

    @RateLimiter(count = 120, limitType = LimitType.USER)
    @GetMapping("/getBigScreenUrl/{deviceId}/{channelId}")
    public AjaxResult getBigScreenUrl(@PathVariable String deviceId, @PathVariable String channelId) {
        requireChannelAccess(deviceId, channelId);
        Stream stream = playService.play(deviceId, channelId, false);
        return stream == null || stream.getHttps_fmp4() == null
                ? AjaxResult.error("视频流暂不可用")
                : AjaxResult.success("success!", stream.getHttps_fmp4());
    }

    @ApiOperation("直播播放")
    @RateLimiter(count = 120, limitType = LimitType.USER)
    @GetMapping("/play/{deviceId}/{channelId}")
    public AjaxResult play(@PathVariable String deviceId, @PathVariable String channelId) {
        requireChannelAccess(deviceId, channelId);
        Stream stream = playService.play(deviceId, channelId, false);
        return stream == null ? AjaxResult.error("视频流暂不可用") : AjaxResult.success("success!", stream);
    }

    @ApiOperation("停止推流")
    @RateLimiter(count = 120, limitType = LimitType.USER)
    @GetMapping("/closeStream/{deviceId}/{channelId}/{streamId}")
    public AjaxResult closeStream(@PathVariable String deviceId, @PathVariable String channelId, @PathVariable String streamId) {
        requireChannelAccess(deviceId, channelId);
        return AjaxResult.success("success!", playService.closeStream(deviceId, channelId, streamId));
    }

    private void requireChannelAccess(String deviceId, String channelId) {
        Long userId = SecurityUtils.getUserId();
        boolean administrator = SecurityUtils.isAdmin(userId);
        SipDeviceChannel query = new SipDeviceChannel();
        query.setDeviceSipId(deviceId);
        query.setChannelSipId(channelId);
        if (!administrator) {
            query.setTenantId(userId);
        }
        boolean allowed = channelMapper.selectSipDeviceChannelList(query).stream().anyMatch(channel ->
                Objects.equals(deviceId, channel.getDeviceSipId())
                        && Objects.equals(channelId, channel.getChannelSipId())
                        && (administrator || Objects.equals(userId, channel.getTenantId())));
        if (!allowed) {
            log.warn("拒绝访问视频通道 userId={}, deviceId={}, channelId={}", userId, deviceId, channelId);
            throw new AccessDeniedException("无权访问该视频通道");
        }
    }
}
