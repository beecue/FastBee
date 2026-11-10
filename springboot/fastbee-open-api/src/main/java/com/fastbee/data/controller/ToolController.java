package com.fastbee.data.controller;

import com.alibaba.fastjson2.JSONObject;
import com.fastbee.common.ProtocolDeCodeService;
import com.fastbee.common.annotation.Log;
import com.fastbee.common.config.RuoYiConfig;
import com.fastbee.common.constant.CacheConstants;
import com.fastbee.common.constant.Constants;
import com.fastbee.common.core.controller.BaseController;
import com.fastbee.common.core.domain.AjaxResult;
import com.fastbee.common.core.domain.entity.SysUser;
import com.fastbee.common.core.domain.model.LoginUser;
import com.fastbee.common.core.iot.response.DeCodeBo;
import com.fastbee.common.core.page.TableDataInfo;
import com.fastbee.common.core.redis.RedisCache;
import com.fastbee.common.enums.BusinessType;
import com.fastbee.common.exception.file.FileNameLengthLimitExceededException;
import com.fastbee.common.utils.StringUtils;
import com.fastbee.common.utils.file.FileUploadUtils;
import com.fastbee.common.utils.file.FileUtils;
import com.fastbee.common.utils.gateway.mq.TopicsUtils;
import com.fastbee.iot.domain.Device;
import com.fastbee.iot.model.*;
import com.fastbee.iot.model.ThingsModels.ThingsModelShadow;
import com.fastbee.iot.service.IDeviceService;
import com.fastbee.iot.service.IToolService;
import com.fastbee.iot.util.VelocityInitializer;
import com.fastbee.iot.util.VelocityUtils;
import com.fastbee.mq.model.ReportDataBo;
import com.fastbee.mq.service.IMqttMessagePublish;
import com.fastbee.mqttclient.MqttClientConfig;
import com.fastbee.mqttclient.PubMqttClient;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.apache.commons.io.IOUtils;
import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static com.fastbee.common.utils.file.FileUploadUtils.getExtension;

/**
 * 产品分类Controller
 *
 * @author kerwincui
 * @date 2021-12-16
 */
@Api(tags = "工具相关")
@RestController
@RequestMapping("/iot/tool")
public class ToolController extends BaseController {
    private static final Logger log = LoggerFactory.getLogger(ToolController.class);
    private static final String MQTT_CALLBACK_TOKEN_HEADER = "X-FastBee-Callback-Token";

    @Resource
    private IDeviceService deviceService;
    @Resource
    private IMqttMessagePublish messagePublish;
    @Resource
    private MqttClientConfig mqttConfig;
    @Resource
    private IToolService toolService;
    // 令牌秘钥
    @Value("${token.secret}")
    private String secret;

    @Resource
    private RedisCache redisCache;

    @Resource
    private ProtocolDeCodeService deCodeService;
    @Resource
    private PubMqttClient mqttClient;

    /**
     * 用户注册
     */
    @ApiOperation("用户注册")
    @PostMapping("/register")
    public AjaxResult register(@RequestBody RegisterUserInput user) {
        String msg = toolService.register(user);
        return StringUtils.isEmpty(msg) ? success() : error(msg);
    }

    /**
     * 获取用户列表
     */
    @ApiOperation("获取用户列表")
    @GetMapping("/userList")
    public TableDataInfo list(SysUser user)
    {
        startPage();
        List<SysUser> list = toolService.selectUserList(user);
        return getDataTable(list);
    }

    /**
     * Web/移动端 MQTT 认证：JWT 签名合法还不够，必须回查登录态与用户状态
     */
    private boolean isValidWebSession(String token) {
        try {
            Claims claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
            String uuid = (String) claims.get(Constants.LOGIN_USER_KEY);
            if (StringUtils.isEmpty(uuid)) {
                return false;
            }
            LoginUser loginUser = redisCache.getCacheObject(CacheConstants.LOGIN_TOKEN_KEY + uuid);
            if (loginUser == null || loginUser.getUser() == null) {
                return false;
            }
            SysUser user = loginUser.getUser();
            return "0".equals(user.getStatus()) && !"2".equals(user.getDelFlag());
        } catch (Exception ex) {
            return false;
        }
    }

    @ApiOperation("mqtt认证")
    @PostMapping("/mqtt/auth")
    public ResponseEntity mqttAuth(@RequestHeader(value = MQTT_CALLBACK_TOKEN_HEADER, required = false) String callbackToken,
                                   @RequestParam(required = false) String clientid,
                                   @RequestParam(required = false) String username,
                                   @RequestParam(required = false) String password,
                                   @RequestParam(value = "peerhost", required = false) String peer) {
        if (!mqttConfig.isTrustedCallback(callbackToken)
                || StringUtils.isEmpty(clientid) || StringUtils.isEmpty(username) || StringUtils.isEmpty(password)) {
            return mqttAuthDenied();
        }
        if (clientid.startsWith("server")) {
            // 服务端认证：配置的账号密码认证
            if (mqttConfig.matchesServerCredentials(username, password)) {
                log.info("-----------服务端mqtt认证成功,clientId:" + clientid + "---------------");
                return ResponseEntity.ok().body("ok");
            } else {
                return toolService.returnUnauthorized(new MqttAuthenticationModel(clientid, username, password), "服务端 MQTT 凭据错误");
            }
        } else if (clientid.startsWith("web") || clientid.startsWith("phone")) {
            // web端和移动端认证：token有效且存在活跃登录态
            String token = password;
            if (StringUtils.isNotEmpty(token) && token.startsWith(Constants.TOKEN_PREFIX)) {
                token = token.replace(Constants.TOKEN_PREFIX, "");
            }
            if (isValidWebSession(token)) {
                log.info("-----------移动端/Web端mqtt认证成功,clientId:" + clientid + "---------------");
                return ResponseEntity.ok().body("ok");
            }
            return toolService.returnUnauthorized(new MqttAuthenticationModel(clientid, username, password),
                    "移动端/Web端mqtt认证失败：登录态已失效或用户不可用");
        } else {
            try {
                return toolService.clientAuth(clientid, username, password, peer);
            } catch (Exception ex) {
                // 旧版 Broker 按 HTTP 状态判断，不能落入会返回 HTTP 200 的全局异常处理。
                log.warn("MQTT 设备认证异常，类型={}", ex.getClass().getSimpleName());
                return mqttAuthDenied();
            }
        }
    }

    private ResponseEntity<String> mqttAuthDenied() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized");
    }

    @ApiOperation("mqtt认证")
    @PostMapping("/mqtt/authv5")
    public ResponseEntity mqttAuthv5(@RequestHeader(value = MQTT_CALLBACK_TOKEN_HEADER, required = false) String callbackToken,
                                     @RequestBody(required = false) JSONObject json) {
        if (!mqttConfig.isTrustedCallback(callbackToken) || json == null) {
            return mqttAuthv5Result(false);
        }
        String clientid = json.getString("clientid");
        String username = json.getString("username");
        String password = json.getString("password");
        if (StringUtils.isEmpty(clientid) || StringUtils.isEmpty(username) || StringUtils.isEmpty(password)) {
            return mqttAuthv5Result(false);
        }
        if (clientid.startsWith("server")) {
            boolean valid = mqttConfig.matchesServerCredentials(username, password);
            if (valid) {
                log.info("-----------服务端mqtt认证成功,clientId:" + clientid + "---------------");
            }
            return mqttAuthv5Result(valid);
        } else if (clientid.startsWith("web") || clientid.startsWith("phone")) {
            // web端和移动端认证：token有效且存在活跃登录态
            String token = password;
            if (StringUtils.isNotEmpty(token) && token.startsWith(Constants.TOKEN_PREFIX)) {
                token = token.replace(Constants.TOKEN_PREFIX, "");
            }
            boolean valid = isValidWebSession(token);
            if (valid) {
                log.info("-----------移动端/Web端mqtt认证成功,clientId:" + clientid + "---------------");
            }
            return mqttAuthv5Result(valid);
        } else {
            try {
                ResponseEntity response = toolService.clientAuthv5(clientid, username, password, json.getString("peerhost"));
                return response.getStatusCode() == HttpStatus.OK ? response : mqttAuthv5Result(false);
            } catch (Exception ex) {
                log.warn("MQTT v5 设备认证异常，类型={}", ex.getClass().getSimpleName());
                return mqttAuthv5Result(false);
            }
        }
    }

    private ResponseEntity<JSONObject> mqttAuthv5Result(boolean allowed) {
        JSONObject result = new JSONObject();
        result.put("is_superuser", false);
        result.put("result", allowed ? "allow" : "deny");
        return ResponseEntity.ok(result);
    }

    @ApiOperation("mqtt钩子处理")
    @PostMapping("/mqtt/webhook")
    public void webHookProcess(@RequestBody MqttClientConnectModel model) {
        try {
            System.out.println("webhook:" + model.getAction());
            // 过滤服务端、web端和手机端
            if (model.getClientid().startsWith("server") || model.getClientid().startsWith("web") || model.getClientid().startsWith("phone")) {
                return;
            }
            // 设备端认证：加密认证（E）和简单认证（S，配置的账号密码认证）
            String[] clientArray = model.getClientid().split("&");
            String authType = clientArray[0];
            String deviceNumber = clientArray[1];
            Long productId = Long.valueOf(clientArray[2]);
            Long userId = Long.valueOf(clientArray[3]);

            Device device = deviceService.selectShortDeviceBySerialNumber(deviceNumber);
            ReportDataBo ruleBo = new ReportDataBo();
            ruleBo.setProductId(device.getProductId());
            ruleBo.setSerialNumber(device.getSerialNumber());
            // 设备状态（1-未激活，2-禁用，3-在线，4-离线）
            if (model.getAction().equals("client_disconnected")) {
                device.setStatus(4);
                deviceService.updateDeviceStatusAndLocation(device, "");
                // 设备掉线后发布设备状态
                messagePublish.publishStatus(device.getProductId(), device.getSerialNumber(), 4, device.getIsShadow(),device.getRssi());
                // 清空保留消息，上线后发布新的属性功能保留消息
                messagePublish.publishProperty(device.getProductId(), device.getSerialNumber(), null,0);
                messagePublish.publishFunction(device.getProductId(), device.getSerialNumber(), null,0);

            } else if (model.getAction().equals("client_connected")) {
                device.setStatus(3);
                deviceService.updateDeviceStatusAndLocation(device, model.getIpaddress());
                // 设备上线后发布设备状态
                messagePublish.publishStatus(device.getProductId(), device.getSerialNumber(), 3, device.getIsShadow(),device.getRssi());
                // 影子模式，发布属性和功能
                if (device.getIsShadow() == 1) {
                    ThingsModelShadow shadow = deviceService.getDeviceShadowThingsModel(device);
                    if (shadow.getProperties().size() > 0) {
                        messagePublish.publishProperty(device.getProductId(), device.getSerialNumber(), shadow.getProperties(),3);
                    }
                    if (shadow.getFunctions().size() > 0) {
                        messagePublish.publishFunction(device.getProductId(), device.getSerialNumber(), shadow.getFunctions(),3);
                    }
                }

            }

        } catch (Exception ex) {
            ex.printStackTrace();
            log.error("发生错误：" + ex.getMessage());
        }
    }

    @ApiOperation("mqtt钩子处理")
    @PostMapping("/mqtt/webhookv5")
    public void webHookProcessv5(@RequestBody JSONObject json) {
        try {
            String clientid = json.getString("clientid");
            String event = json.getString("event");
            String peername = json.getString("peername");  // 类似 127.0.0.111.11.11.11:8812
            String ipAddress=peername;
            if(peername.indexOf(":")!=-1){
                ipAddress = peername.substring(0,peername.indexOf(":"));
            }
            log.info("webhook:" + event + ",clientid:" + clientid);
            // 过滤服务端、web端和手机端
            if (clientid.startsWith("server") || clientid.startsWith("web") || clientid.startsWith("phone")) {
                return;
            }
            // 设备端认证：加密认证（E）和简单认证（S，配置的账号密码认证）
            String[] clientArray = clientid.split("&");
            String deviceNumber = clientArray[1];

            Device device = deviceService.selectShortDeviceBySerialNumber(deviceNumber);
            ReportDataBo ruleBo = new ReportDataBo();
            ruleBo.setProductId(device.getProductId());
            ruleBo.setSerialNumber(device.getSerialNumber());
            // 设备状态（1-未激活，2-禁用，3-在线，4-离线）
            if (event.equals("client.disconnected")) {
                device.setStatus(4);
                deviceService.updateDeviceStatusAndLocation(device, "");
                // 设备掉线后发布设备状态
                messagePublish.publishStatus(device.getProductId(), device.getSerialNumber(), 4, device.getIsShadow(),device.getRssi());
                // 清空保留消息，上线后发布新的属性功能保留消息
                messagePublish.publishProperty(device.getProductId(), device.getSerialNumber(), null,0);
                messagePublish.publishFunction(device.getProductId(), device.getSerialNumber(), null,0);
            } else if (event.equals("client.connected")) {
                device.setStatus(3);
                deviceService.updateDeviceStatusAndLocation(device, ipAddress);
                // 设备掉线后发布设备状态
                messagePublish.publishStatus(device.getProductId(), device.getSerialNumber(), 3, device.getIsShadow(),device.getRssi());
            } else if(event.equals("session.subscribed")){
                // 影子模式，发布属性和功能
                if (device.getIsShadow() == 1) {
                    ThingsModelShadow shadow = deviceService.getDeviceShadowThingsModel(device);
                    if (shadow.getProperties().size() > 0) {
                        messagePublish.publishProperty(device.getProductId(), device.getSerialNumber(), shadow.getProperties(),3);
                    }
                    if (shadow.getFunctions().size() > 0) {
                        messagePublish.publishFunction(device.getProductId(), device.getSerialNumber(), shadow.getFunctions(),3);
                    }
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            log.error("发生错误：" + ex.getMessage());
        }
    }


    @ApiOperation("获取NTP时间")
    @GetMapping("/ntp")
    public JSONObject ntp(@RequestParam Long deviceSendTime) {
        JSONObject ntpJson = new JSONObject();
        ntpJson.put("deviceSendTime", deviceSendTime);
        ntpJson.put("serverRecvTime", System.currentTimeMillis());
        ntpJson.put("serverSendTime", System.currentTimeMillis());
        return ntpJson;
    }

    /**
     * 文件上传
     */
    @PostMapping("/upload")
    @ApiOperation("文件上传")
    public AjaxResult uploadFile(MultipartFile file) throws Exception {
        try {
            String filePath = RuoYiConfig.getProfile();
            // 文件名长度限制
            int fileNamelength = file.getOriginalFilename().length();
            if (fileNamelength > FileUploadUtils.DEFAULT_FILE_NAME_LENGTH) {
                throw new FileNameLengthLimitExceededException(FileUploadUtils.DEFAULT_FILE_NAME_LENGTH);
            }
            // 文件类型限制
            // assertAllowed(file, MimeTypeUtils.DEFAULT_ALLOWED_EXTENSION);

            // 获取文件名和文件类型
            String fileName = file.getOriginalFilename();
            String extension = getExtension(file);
            //设置日期格式
            SimpleDateFormat df = new SimpleDateFormat("yyyy-MMdd-HHmmss");
            fileName = "/iot/" + getLoginUser().getUserId().toString() + "/" + df.format(new Date()) + "." + extension;
            //创建目录
            File desc = new File(filePath + File.separator + fileName);
            if (!desc.exists()) {
                if (!desc.getParentFile().exists()) {
                    desc.getParentFile().mkdirs();
                }
            }
            // 存储文件
            file.transferTo(desc);

            String url = "/profile" + fileName;
            AjaxResult ajax = AjaxResult.success();
            ajax.put("fileName", url);
            ajax.put("url", url);
            return ajax;
        } catch (Exception e) {
            return AjaxResult.error(e.getMessage());
        }
    }

    /**
     * 下载文件
     */
    @ApiOperation("文件下载")
    @GetMapping("/download")
    public void download(String fileName, HttpServletResponse response, HttpServletRequest request) {
        try {
//            if (!FileUtils.checkAllowDownload(fileName)) {
//                throw new Exception(StringUtils.format("文件名称({})非法，不允许下载。 ", fileName));
//            }
            String filePath = RuoYiConfig.getProfile();
            // 资源地址
            String downloadPath = filePath + fileName.replace("/profile", "");
            // 下载名称
            String downloadName = StringUtils.substringAfterLast(downloadPath, "/");
            response.setContentType(MediaType.APPLICATION_OCTET_STREAM_VALUE);
            FileUtils.setAttachmentResponseHeader(response, downloadName);
            FileUtils.writeBytes(downloadPath, response.getOutputStream());
        } catch (Exception e) {
            log.error("下载文件失败", e);
        }
    }

    /**
     * 批量生成代码
     */
    @Log(title = "SDK生成", businessType = BusinessType.GENCODE)
    @GetMapping("/genSdk")
    @ApiOperation("生成SDK")
    public void genSdk(HttpServletResponse response, int deviceChip) throws IOException {
        byte[] data = downloadCode(deviceChip);
        genSdk(response, data);
    }

    /**
     * 生成zip文件
     */
    private void genSdk(HttpServletResponse response, byte[] data) throws IOException {
        response.reset();
        response.addHeader("Access-Control-Allow-Origin", "*");
        response.addHeader("Access-Control-Expose-Headers", "Content-Disposition");
        response.setHeader("Content-Disposition", "attachment; filename=\"fastbee.zip\"");
        response.addHeader("Content-Length", "" + data.length);
        response.setContentType("application/octet-stream; charset=UTF-8");
        IOUtils.write(data, response.getOutputStream());
    }

    /**
     * 批量生成代码（下载方式）
     *
     * @param deviceChip
     * @return 数据
     */
    public byte[] downloadCode(int deviceChip) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        ZipOutputStream zip = new ZipOutputStream(outputStream);
//        generatorCode(deviceChip, zip);
        IOUtils.closeQuietly(zip);
        return outputStream.toByteArray();
    }

    /**
     * 查询表信息并生成代码
     */
    private void generatorCode(int deviceChip, ZipOutputStream zip) {
        VelocityInitializer.initVelocity();

        VelocityContext context = VelocityUtils.prepareContext(deviceChip);

        // 获取模板列表
        List<String> templates = VelocityUtils.getTemplateList("");
        for (String template : templates) {
            // 渲染模板
            StringWriter sw = new StringWriter();
            Template tpl = Velocity.getTemplate(template, Constants.UTF8);
            tpl.merge(context, sw);
            try {
                // 添加到zip
                zip.putNextEntry(new ZipEntry(VelocityUtils.getFileName(template)));
                IOUtils.write(sw.toString(), zip, Constants.UTF8);
                IOUtils.closeQuietly(sw);
                zip.flush();
                zip.closeEntry();
            } catch (IOException e) {
                System.out.println("渲染模板失败");
            }
        }
    }

    @GetMapping("/getTopics")
    @ApiOperation("获取所有下发的topic")
    public AjaxResult getTopics(Boolean isSimulate){
        return AjaxResult.success(TopicsUtils.getAllGet(isSimulate));
    }

    @GetMapping("/decode")
    @ApiOperation("指令编码")
    public AjaxResult decode(DeCodeBo bo){
        return AjaxResult.success(deCodeService.protocolDeCode(bo));
    }

}
