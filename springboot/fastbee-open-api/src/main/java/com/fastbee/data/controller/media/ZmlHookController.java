package com.fastbee.data.controller.media;

import com.alibaba.fastjson.JSONObject;
import com.fastbee.sip.service.IZmlHookService;
import com.fastbee.sip.service.MediaAccessTokens;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.function.Function;

@Api(tags = "流媒体Hook")
@RestController
@RequestMapping("/zlmhook")
public class ZmlHookController
{

    @Autowired
    private IZmlHookService zmlHookService;

    @Autowired
    private MediaAccessTokens mediaAccessTokens;

    @ApiOperation("访问流媒体服务器上的文件时触发回调")
    @ResponseBody
    @PostMapping(value = "/on_http_access", produces = "application/json;charset=UTF-8")
    public ResponseEntity<String> onHttpAccess(@RequestBody JSONObject json,
            @RequestParam(value = "hookToken", required = false) String token) {
        return handle(json, token, zmlHookService::onHttpAccess);
    }
    @ApiOperation("播放器鉴权事件回调")
    @ResponseBody
    @PostMapping(value = "/on_play", produces = "application/json;charset=UTF-8")
    public ResponseEntity<String> onPlay(@RequestBody JSONObject json,
            @RequestParam(value = "hookToken", required = false) String token) {
        return handle(json, token, zmlHookService::onPlay);
    }
    @ApiOperation("rtsp/rtmp/rtp推流鉴权事件回调")
    @ResponseBody
    @PostMapping(value = "/on_publish", produces = "application/json;charset=UTF-8")
    public ResponseEntity<String> onPublish(@RequestBody JSONObject json,
            @RequestParam(value = "hookToken", required = false) String token) {
        return handle(json, token, zmlHookService::onPublish);
    }
    @ApiOperation("流无人观看时事件回调")
    @ResponseBody
    @PostMapping(value = "/on_stream_none_reader", produces = "application/json;charset=UTF-8")
    public ResponseEntity<String> onStreamNoneReader(@RequestBody JSONObject json,
            @RequestParam(value = "hookToken", required = false) String token) {
        return handle(json, token, zmlHookService::onStreamNoneReader);
    }
    @ApiOperation("流未找到事件回调")
    @ResponseBody
    @PostMapping(value = "/on_stream_not_found", produces = "application/json;charset=UTF-8")
    public ResponseEntity<String> onStreamNotFound(@RequestBody JSONObject json,
            @RequestParam(value = "hookToken", required = false) String token) {
        return handle(json, token, zmlHookService::onStreamNotFound);
    }
    @ApiOperation("流注册或注销时触发此事件回调")
    @ResponseBody
    @PostMapping(value = "/on_stream_changed", produces = "application/json;charset=UTF-8")
    public ResponseEntity<String> onStreamChanged(@RequestBody JSONObject json,
            @RequestParam(value = "hookToken", required = false) String token) {
        return handle(json, token, zmlHookService::onStreamChanged);
    }
    @ApiOperation("流量统计事件回调")
    @ResponseBody
    @PostMapping(value = "/on_flow_report", produces = "application/json;charset=UTF-8")
    public ResponseEntity<String> onFlowReport(@RequestBody JSONObject json,
            @RequestParam(value = "hookToken", required = false) String token) {
        return handle(json, token, zmlHookService::onFlowReport);
    }
    @ApiOperation("rtp服务器长时间未收到数据超时回调")
    @ResponseBody
    @PostMapping(value = "/on_rtp_server_timeout", produces = "application/json;charset=UTF-8")
    public ResponseEntity<String> onRtpServerTimeout(@RequestBody JSONObject json,
            @RequestParam(value = "hookToken", required = false) String token) {
        return handle(json, token, zmlHookService::onRtpServerTimeout);
    }

    @ApiOperation("rtp发送停止回调")
    @ResponseBody
    @PostMapping(value = "/on_send_rtp_stopped", produces = "application/json;charset=UTF-8")
    public ResponseEntity<String> onSendRtpStopped(@RequestBody JSONObject json,
            @RequestParam(value = "hookToken", required = false) String token) {
        return handle(json, token, zmlHookService::onSendRtpStopped);
    }

    @ApiOperation("录制mp4完成后通知事件回调")
    @ResponseBody
    @PostMapping(value = "/on_record_mp4", produces = "application/json;charset=UTF-8")
    public ResponseEntity<String> onRecordMp4(@RequestBody JSONObject json,
            @RequestParam(value = "hookToken", required = false) String token) {
        return handle(json, token, zmlHookService::onRecordMp4);
    }

    @ApiOperation("流媒体服务器启动回调")
    @ResponseBody
    @PostMapping(value = "/on_server_started", produces = "application/json;charset=UTF-8")
    public ResponseEntity<String> onServerStarted(@RequestBody JSONObject json,
            @RequestParam(value = "hookToken", required = false) String token) {
        return handle(json, token, zmlHookService::onServerStarted);
    }

    @ApiOperation("流媒体服务器心跳回调")
    @ResponseBody
    @PostMapping(value = "/on_server_keepalive", produces = "application/json;charset=UTF-8")
    public ResponseEntity<String> onServerKeepalive(@RequestBody JSONObject json,
            @RequestParam(value = "hookToken", required = false) String token) {
        return handle(json, token, zmlHookService::onServerKeepalive);
    }

    @ApiOperation("流媒体服务器存活回调")
    @ResponseBody
    @PostMapping(value = "/on_server_exited", produces = "application/json;charset=UTF-8")
    public ResponseEntity<String> onServerExited(@RequestBody JSONObject json,
            @RequestParam(value = "hookToken", required = false) String token) {
        return handle(json, token, zmlHookService::onServerExited);
    }

    private ResponseEntity<String> handle(JSONObject body, String token, Function<JSONObject, JSONObject> handler) {
        if (body == null || !mediaAccessTokens.allowsHook(body.getString("mediaServerId"), token)) {
            JSONObject denied = new JSONObject();
            denied.put("code", 401);
            denied.put("msg", "Unauthorized media server");
            return new ResponseEntity<>(denied.toString(), HttpStatus.UNAUTHORIZED);
        }
        return new ResponseEntity<>(handler.apply(body).toString(), HttpStatus.OK);
    }
}
