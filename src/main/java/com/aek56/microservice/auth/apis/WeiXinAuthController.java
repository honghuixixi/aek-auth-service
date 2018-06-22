package com.aek56.microservice.auth.apis;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mobile.device.Device;
import org.springframework.mobile.device.DevicePlatform;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.aek56.microservice.auth.common.BaseController;
import com.aek56.microservice.auth.common.Result;
import com.aek56.microservice.auth.entity.SysTenant;
import com.aek56.microservice.auth.entity.SysUser;
import com.aek56.microservice.auth.entity.WxSysUser;
import com.aek56.microservice.auth.enums.TenantType;
import com.aek56.microservice.auth.exception.ExceptionFactory;
import com.aek56.microservice.auth.model.security.AuthUser;
import com.aek56.microservice.auth.model.security.TokenInfo;
import com.aek56.microservice.auth.redis.RedisRepository;
import com.aek56.microservice.auth.security.JwtTokenUtil;
import com.aek56.microservice.auth.security.service.SystemService;
import com.aek56.microservice.auth.util.MapUtils;
import com.aek56.microservice.auth.util.SecurityUtil;
import com.aek56.microservice.auth.util.ThreadHolder;
import com.aek56.microservice.auth.weixin.SysUserService;
import com.aek56.microservice.auth.weixin.WeiXinConstants;
import com.aek56.microservice.auth.weixin.WeiXinService;
import com.aek56.microservice.auth.weixin.WeiXinSignUtil;
import com.aek56.microservice.auth.weixin.WeiXinUtil;
import com.aek56.microservice.auth.weixin.WxSysUserService;
import com.aek56.microservice.auth.weixin.config.WeiXinConfig;
import com.aek56.microservice.auth.weixin.message.template.TemplateMsgResult;
import com.aek56.microservice.auth.weixin.message.template.WeiXinRepairTemplate;
import com.aek56.microservice.auth.weixin.message.template.WeiXinServiceTemplate;
import com.aek56.microservice.auth.weixin.request.WeiXinAutoLoginRequest;
import com.aek56.microservice.auth.weixin.request.WeiXinBindingRequest;
import com.aek56.microservice.auth.weixin.request.WeiXinRepairMessageRequest;
import com.aek56.microservice.auth.weixin.request.WeiXinServiceMessageRequest;
import com.aek56.microservice.auth.weixin.token.WeiXinAccessToken;
import com.aek56.microservice.auth.weixin.token.WeiXinJsCode2Session;
import com.aek56.microservice.auth.weixin.token.WeiXinOauth2Token;
import com.aek56.microservice.auth.weixin.userinfo.SNSUserInfo;
import com.github.pagehelper.StringUtil;
import com.google.gson.Gson;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;

/**
 * 接收微信验证消息
 *	
 * @author HongHui
 * @date   2017年11月29日
 */
@Api(value="WeiXinAuthController",description="微信操作",tags={"WeiXinAuthController-微信操作接口"})
@RestController
public class WeiXinAuthController extends BaseController{
	
	private static final Log logger = LogFactory.getLog(WeiXinAuthController.class);
	
	@Value("${jwt.header}")
	private String tokenHeader;
	@Value("${cookie.domain:aek.com}")
	private String cookieDomain;
	@Autowired
	private AuthenticationManager authenticationManager;
	@Autowired
	private WeiXinService weiXinService;
	@Autowired
	private WxSysUserService wxSysUserService;
	@Autowired
	private SysUserService sysUserService;
	@Autowired
	private SystemService systemService;
	@Autowired
	private PasswordEncoder passwordEncoder;
	@Autowired
	private JwtTokenUtil jwtTokenUtil;
	@Autowired
	private RedisRepository redisRepository;
	//微信公众号相关配置
	@Autowired
	private WeiXinConfig weiXinConfig;
	
	/**
	 * 验证微信认证请求
	 */
	@ApiOperation(value = "验证微信认证请求", httpMethod = "GET")
	@ApiResponse(code = 0, message = "OK", response = String.class)
	@RequestMapping(value="/weixin",method=RequestMethod.GET)
	@ResponseBody
	public String oauthWeiXinSignature(HttpServletRequest request,HttpServletResponse response){
		logger.debug("=================验证微信请求=================");
		String signature = request.getParameter("signature");
		String timestamp = request.getParameter("timestamp");
		String nonce = request.getParameter("nonce");
		String echostr = request.getParameter("echostr");
		logger.debug("#####微信加密签名：" + signature);
		logger.debug("#####时间戳：" + timestamp);
		logger.debug("#####随机数：" + nonce);
		logger.debug("#####随机字符串：" + echostr);
		//通过检验signature对请求进行校验，若校验成功则原样返回echostr，表示接入成功，否则接入失败
		if(WeiXinSignUtil.checkSignature(weiXinConfig.getToken(),signature, timestamp, nonce)){
			return echostr;
		}	
		return null;
	}
	
	/**
	 * 处理微信服务器发送过来的消息
	 */
	@ApiOperation(value = "处理微信服务器发送过来的消息", httpMethod = "POST")
	@ApiResponse(code = 0, message = "OK", response = String.class)
	@RequestMapping(value="/weixin",method=RequestMethod.POST)
	@ResponseBody
	public String processWeiXinRequest(HttpServletRequest request,HttpServletResponse response) throws UnsupportedEncodingException{
		logger.debug("=================处理微信消息请求=================");
		//处理微信消息的接收、处理、响应
		//将请求、响应的编码均设为UTF-8，防止中文乱码
		request.setCharacterEncoding("UTF-8");
		response.setCharacterEncoding("UTF-8");
		// 调用核心业务类接收消息、处理消息
		String respXml = weiXinService.processWeiXinRequest(request);
		return respXml;
	}
	
	/**
	 * 获取最新微信access_token
	 */
	@ApiOperation(value = "获取最新微信access_token", httpMethod = "POST")
	@ApiResponse(code = 0, message = "OK", response = String.class)
	@RequestMapping(value="/weixin/token",method=RequestMethod.GET)
	@ResponseBody
	public String getWeiXinAccessToken(){
		WeiXinAccessToken weiXinAccessToken = weiXinService.getWeiXinAccessToken(weiXinConfig.getAppId(),weiXinConfig.getAppSecret());
		if(null != weiXinAccessToken){
			return weiXinAccessToken.getAccessToken();
		}
		return null;
	}
	
	/**
	 * 授权后的回调请求处理
	 * @param request
	 * @param response
	 * @throws IOException 
	 * @throws ServletException 
	 */
	@RequestMapping(value="/weixin/callback",method=RequestMethod.GET)
	public void oauthCallBack(HttpServletRequest request, HttpServletResponse response){
		logger.info("============授权后的回调请求处理================");
		try{
			request.setCharacterEncoding("utf-8");
	        response.setCharacterEncoding("utf-8");
	        // 用户同意授权后，能获取到code
	        String code = request.getParameter("code");
	        String state = request.getParameter("state");
	        logger.info("code="+code);
	        logger.info("state="+state);
	        // 用户同意授权
	        if (!"authdeny".equals(code)) {
	            // 获取网页授权access_token
	        	WeiXinOauth2Token weixinOauth2Token = WeiXinUtil.getOauth2AccessToken(weiXinConfig.getOauth2AccessTokenUrl(),weiXinConfig.getAppId(), weiXinConfig.getAppSecret(), code);
	            // 网页授权接口访问凭证
	            String accessToken = weixinOauth2Token.getAccessToken();
	            // 用户标识
	            String openId = weixinOauth2Token.getOpenId();
	            // 获取用户信息
	            SNSUserInfo snsUserInfo = WeiXinUtil.getSNSUserInfo(weiXinConfig.getSnsUserInfoUrl(),accessToken, openId);
	            logger.info("用户信息="+snsUserInfo.toString());
	            // 设置要传递的参数
	            //request.setAttribute("snsUserInfo", snsUserInfo);
	            //request.setAttribute("state", state);
	            //判断当前openId是否已经绑定设备平台用户
	            WxSysUser wxSysUser = wxSysUserService.getWxSysUser(snsUserInfo.getOpenId());
	            //对openId加密处理
	            openId = SecurityUtil.encryptDes(snsUserInfo.getOpenId());
	            String unionId = snsUserInfo.getUnionId();
	            if(StringUtils.isNotEmpty(unionId)){
	            	unionId = SecurityUtil.encryptDes(unionId);
	            }
	            //对昵称加密
	            String wxNickName = snsUserInfo.getNickname();
	            if(StringUtils.isNotEmpty(wxNickName)) {
	                wxNickName = SecurityUtil.encryptDes(wxNickName);
	            }
	            System.out.println("微信callback用户信息="+snsUserInfo.toString());
	            System.out.println("openid="+openId);
	            System.out.println("unionId="+unionId);
	            if(null == wxSysUser){
	            	//未绑定 重定向绑定页面
	            	response.sendRedirect(weiXinConfig.getBandingPageUrl()+"?openId="+openId+"&unionId="+unionId+"&wxNickName="+wxNickName);
	            } else {
	                //更新微信用户昵称
	                wxSysUser.setWxNickName(snsUserInfo.getNickname());
	                wxSysUserService.updateWxSysUser(wxSysUser);
	            	//已绑定 重定向绑定成功页面
	            	response.sendRedirect(weiXinConfig.getBandingSuccessPageUrl()+"?openId="+openId+"&unionId="+unionId+"&wxNickName="+wxNickName);
	            }
	        }
		} catch (Exception e){
			e.printStackTrace();
			try {
				//跳转异常页面
				response.sendRedirect(weiXinConfig.getBandingErrorPageUrl());
			} catch (IOException e1) {
				e1.printStackTrace();
			}
		}
	}
	
	/**
	 * 根据code获取微信用户openId
	 * @param code
	 * @return
	 */
	@ApiOperation(value = "根据code获取微信用户openId", httpMethod = "GET")
	@ApiResponse(code = 0, message = "OK", response = Result.class)
	@RequestMapping(value="/weixin/getOpenId",method=RequestMethod.GET)
	public Result<SNSUserInfo> getWeiXinUserOpenId(@RequestParam(required = true) String code){
		logger.info("==============根据code获取微信用户信息==============");
		logger.info("用户同意授权后获取code="+code);
		// 获取网页授权access_token
    	WeiXinOauth2Token weixinOauth2Token = WeiXinUtil.getOauth2AccessToken(weiXinConfig.getOauth2AccessTokenUrl(),weiXinConfig.getAppId(), weiXinConfig.getAppSecret(), code);
        // 网页授权接口访问凭证
        String accessToken = weixinOauth2Token.getAccessToken();
        // 用户标识
        String openId = weixinOauth2Token.getOpenId();
        // 获取用户信息
        SNSUserInfo snsUserInfo = WeiXinUtil.getSNSUserInfo(weiXinConfig.getSnsUserInfoUrl(),accessToken, openId);
		return response(snsUserInfo);
	}
	
	/**
	 * 系统用户与微信公众号用户绑定
	 * @param request
	 * @param response
	 * @return
	 */
	@ApiOperation(value = "系统用户与微信公众号用户绑定", httpMethod = "POST")
	@ApiResponse(code = 0, message = "OK", response = Result.class)
	@PostMapping(value="/weixin/binding")
	public Result<Object> weiXinBinding(@RequestBody WeiXinBindingRequest request,HttpServletResponse response){
		try{
			String username = request.getUsername();
			String password = request.getPassword();
			String openId = request.getOpenId();
			String unionId = request.getUnionId();
			String wxNickName = request.getWxNickName();
			logger.info("username="+username);
			logger.info("password="+password);
			logger.info("openId="+openId);
			logger.info("unionId="+unionId);
			logger.info("wxNickName="+wxNickName);
			if (StringUtils.isBlank(username)){
				throw ExceptionFactory.create("B_001");
			} 
			SysUser user = systemService.getUserByLoginIdNoTenant(username);
			if (null == user) {
				throw ExceptionFactory.create("B_002");
			}
			if(StringUtils.isBlank(password)) {
				throw ExceptionFactory.create("B_003");
			}
			//密码校验
			if (!passwordEncoder.matches(password, user.getPassword())) {
				throw ExceptionFactory.create("B_004");
			}
			//账号停用
			if(!user.getEnable()){
				throw ExceptionFactory.create("B_005");
			}
			SysTenant sysTenant = systemService.getTenantInfo(user.getTenantId());
			//机构删除
			if(sysTenant.getDelFlag()){
				throw ExceptionFactory.create("B_006");
			}
			//账号待审核状态
			if(null != sysTenant && sysTenant.getAuditStatus() == 1){
				throw ExceptionFactory.create("B_007");
			}
			//账号审核未通过状态
			if(null != sysTenant && sysTenant.getAuditStatus() == 4){
				throw ExceptionFactory.create("B_008");
			}
			//机构被禁用
			if (!systemService.isTenantEnable(user.getTenantId())) {
				throw ExceptionFactory.create("B_009");
			}
			if(StringUtils.isBlank(openId)) {
				throw ExceptionFactory.create("B_010");
			}
			
			//解密
			openId = SecurityUtil.decryptDes(openId);
			if(wxSysUserService.exist(openId)){
				throw ExceptionFactory.create("B_011");
			}
			WxSysUser wxSysUser = wxSysUserService.getWxSysUser(user.getId());
			if(null != wxSysUser){
				throw ExceptionFactory.create("B_012");
			}
			logger.info("unionId="+unionId);
			//解密
			if(StringUtils.isNotBlank(unionId)&&!"null".equals(unionId)){
				unionId = SecurityUtil.decryptDes(unionId);
			}
			//解密
			if(StringUtils.isNotBlank(wxNickName) && !"null".equals(wxNickName)) {
			    wxNickName = SecurityUtil.decryptDes(wxNickName);
			}
			logger.info("=====================================");
			WxSysUser sysUser = new WxSysUser();
			sysUser.setOpenId(openId);
			sysUser.setUnionId(unionId);
			sysUser.setUserId(user.getId());
			sysUser.setPassword(SecurityUtil.encryptDes(password));
			sysUser.setEnable(true);
			sysUser.setWxNickName(wxNickName);
			logger.info("绑定用户信息="+sysUser.toString());
			wxSysUserService.saveWxSysUser(sysUser);
		}catch(Exception e){
			e.printStackTrace();
		}
		return response();
	}
	
	/**
	 * 判断系统用户与微信公众号用户是否绑定
	 * @param request
	 * @param response
	 * @return
	 */
	@ApiOperation(value = "判断系统用户与微信公众号用户是否绑定", httpMethod = "GET")
	@ApiResponse(code = 0, message = "OK", response = Boolean.class)
	@GetMapping(value="/weixin/isbinding")
	public Boolean isWeiXinBinding(@RequestParam(required = true) String openId){
		if(wxSysUserService.exist(openId)){
			return true;
		}
		return false;
	}
	
	/**
	 * 小程序判断token是否有效
	 * @param request
	 * @param response
	 * @return
	 */
	@ApiOperation(value = "判断token是否有效", httpMethod = "GET")
	@ApiResponse(code = 0, message = "OK", response = Boolean.class)
	@GetMapping(value="/weixin/validToken")
	public Boolean validWeiXinToken(@RequestParam(required = true) String token){
		System.out.println("==============");
		return jwtTokenUtil.validateToken(token);
	}
	
	/**
	 * 绑定微信公众号的用户自动登录小程序
	 * @param request
	 * @param device
	 * @param response
	 * @return
	 */
	@ApiOperation(value = "绑定微信公众号的用户自动登录小程序", httpMethod = "POST")
	@ApiResponse(code = 0, message = "OK", response = Map.class)
	@PostMapping(value = "/weixin/autologin")
	public Map<String, Object> weiXinAutoLogin(@RequestBody WeiXinAutoLoginRequest request, Device device,
			HttpServletResponse response) {
		logger.debug(device);
		String deviceId = request.getDeviceId();
		Map<String, Object> map = new HashMap<String, Object>();
		if (deviceId == null || deviceId.length() < 10) {// 终端编号不能小于10
			map.put("code", 401);
			map.put("msg", "设备ID不能少于10位.");
			return map;
		}
		//微信用户授权后code
		String code = request.getCode();
		logger.info("微信用户同意授权后获取code="+code);
		
		if (StringUtils.isBlank(code)){
			map.put("code", 403);
			map.put("msg", "code不能为空");
			return map;
		} 
		
		WeiXinJsCode2Session weiXinJsCode2Session = WeiXinUtil.getJsCode2Session(weiXinConfig.getJsCode2SessionUrl(), weiXinConfig.getMiniAppId(), weiXinConfig.getMiniAppSecret(), code);
		if(null == weiXinJsCode2Session){
			map.put("code", 403);
			map.put("msg", "获取用户openid失败");
			return map;
		}
        // 用户标识
        String miniOpenId = weiXinJsCode2Session.getOpenId();
        // 用户唯一标识
        String unionId = weiXinJsCode2Session.getUnionid();
        System.out.println("小程序自动登录：mimiOpenId="+miniOpenId);
        System.out.println("小程序自动登录：unionId="+unionId);
        WxSysUser wxSysUser = wxSysUserService.getWxSysUserByUnionId(unionId);
        if(null == wxSysUser){
        	wxSysUser = wxSysUserService.getWxSysUserByMiniOpenId(miniOpenId);
        	if(null == wxSysUser){
        		map.put("code", "411");
				map.put("msg", "您未绑定的设备平台用户");
				return map;
        	}else{
        		if(StringUtil.isEmpty(wxSysUser.getUnionId())){
        			//更新
    				wxSysUser.setUnionId(unionId);
    				wxSysUserService.updateWxSysUser(wxSysUser);
        		}
        	}
        }else{
        	if(StringUtil.isEmpty(wxSysUser.getMiniOpenId())){
        		//更新
				wxSysUser.setMiniOpenId(miniOpenId);
				wxSysUserService.updateWxSysUser(wxSysUser);
        	}
        }
		
		SysUser user = systemService.getUserById(wxSysUser.getUserId());
		if (null == user) {
			map.put("code", "411");
			map.put("msg", "您绑定的用户不存在");
			return map;
		}
		if(!user.getEnable()){
			map.put("code", "411");
			map.put("msg", "您绑定的用户被禁用,请联系管理员");
			return map;
		}
		
		// 机构未审核或申请被拒绝
		SysTenant sysTenant = systemService.getTenantInfo(user.getTenantId());
		if(null != sysTenant && sysTenant.getAuditStatus() == 1){
			map.put("code", "414");
			map.put("msg", "您的申请正在审核中");
			return map;
		}
		if(null != sysTenant && sysTenant.getAuditStatus() == 4){
			map.put("code", "414");
			map.put("msg", "您的申请被拒绝");
			return map;
		}

		// 机构被禁用
		if (!systemService.isTenantEnable(user.getTenantId())) {
			map.put("code", "414");
			map.put("msg", "机构已经被停用");
			return map;
		}

		String key = deviceId + ":" + JwtTokenUtil.REDIS_PREFIX_AUTH + user.getMobile();
		String authJson = redisRepository.get(key);
		if (StringUtils.isNotBlank(authJson)) {
			Gson gson = new Gson();
			TokenInfo tokenInfo = gson.fromJson(authJson, TokenInfo.class);
			map.put("code", 402);
			map.put("tokenKey", tokenHeader);
			map.put("token", tokenInfo.getToken());
			map.put("msg", "已登录.");
			
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			AuthUser userDetail = (AuthUser) authentication.getPrincipal();
			userDetail.setPassword(null);
			map.put("user_details", userDetail);
			
			// set accessToken cookie
			final Cookie cookie = new Cookie(tokenHeader, tokenInfo.getToken());
			cookie.setHttpOnly(true);
			cookie.setMaxAge(jwtTokenUtil.getExpiration().intValue());
			cookie.setDomain(cookieDomain);
			cookie.setPath("/");
			response.addCookie(cookie);
			return map;
		}
		ThreadHolder.set(request.getDeviceId());
		// Perform the security
		final Authentication authentication = authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(user.getMobile(), SecurityUtil.decryptDes(wxSysUser.getPassword())));
		SecurityContextHolder.getContext().setAuthentication(authentication);
		AuthUser userDetails = (AuthUser) authentication.getPrincipal();
		userDetails.setDeviceId(deviceId);
		userDetails.setDeptId(user.getDeptId());

		// 更新 登陆信息
		Map<String, Object> loginInfo = new HashMap<>();
		String ip = "UNKOWN";
		ip = systemService.getRemoteIp();
		loginInfo.put("id", user.getId());
		loginInfo.put("ip", ip);
		Calendar cal = Calendar.getInstance();
		loginInfo.put("loginTime", cal.getTime());

		String device_type = "UNKOWN";
		if (device.getDevicePlatform() == DevicePlatform.IOS)
			device_type = "IOS";
		else if (device.getDevicePlatform() == DevicePlatform.ANDROID)
			device_type = "ANDROID";
		else {
			device_type = "PC";
		}
		loginInfo.put("device", device_type);
		systemService.updateLoginInfo(loginInfo);

		// 获取权限，数据范围
		List<Map<String, Object>> dataScopes = systemService.findDataScopeListByUser(user.getId(), user.getTenantId());

		final String token = jwtTokenUtil.generateToken(userDetails, device, dataScopes);
		Map<String, Object> tokenMap = new HashMap<>();
		tokenMap.put("token", token);
		cal.add(Calendar.SECOND, jwtTokenUtil.getExpiration().intValue());
		tokenMap.put("expire", cal.getTime());
		tokenMap.put("token_type", "Bearer");
		tokenMap.put("code", 200);
		//返回当前用户信息
		tokenMap.put("user_details", userDetails);

		// set access_token cookie
		final Cookie cookie = new Cookie(tokenHeader, token);
		cookie.setHttpOnly(true);
		cookie.setMaxAge(jwtTokenUtil.getExpiration().intValue());
		cookie.setDomain(cookieDomain);
		cookie.setPath("/");
		response.addCookie(cookie);

		return tokenMap;
	}
	
	
	/**
	 * 发送微信维修消息
	 * @return
	 */
	@PostMapping(value = "/weixin/send/repair/message")
	@ApiOperation(value = "发送微信维修消息", httpMethod = "POST")
	@ApiResponse(code = 0, message = "OK", response = Result.class)
	public Result<List<Map<String, Object>>> sendWeiXinRepairMessage(@RequestBody WeiXinRepairMessageRequest request){
		logger.debug("==============发送微信公众号维修消息==============");
		List<Map<String, Object>> responseMapList = new ArrayList<Map<String, Object>>();
		Map<String, Object> map = new HashMap<String, Object>();
		//获取机构下拥有接单、维修、验收权限用户集合
		/*List<SysUser> sysUsers = sysUserService.getWeiXinRepairMessageUsers(request.getTenantId(), request.getType());
		if(sysUsers.size() == 0){
			map.put("code", "401");
			map.put("msg", "该机构下没有拥有"+WeiXinConstants.WEIXIN_REPAIR_MESSAGE_TYPE_MAP.get(request.getType()) + "权限的用户");
			responseMapList.add(map);
			return response(responseMapList);
		}*/
		//发送消息用户集合
		List<SysUser> sysUsers = new ArrayList<SysUser>();
		//接单，指定接单人消息可见
		if (request.getType() == 1) {
		    SysUser sysUser = systemService.getUserById(request.getTakeOrderId());
		    sysUsers.add(sysUser);
		} else if (request.getType() == 2) {
		    //维修，指定维修人消息可见
		    SysUser sysUser = systemService.getUserById(request.getRepairId());
		    sysUsers.add(sysUser);
		} else if (request.getType() == 3) {
		    //验收,设备所在科室人员
		    sysUsers = systemService.getUserByTenantIdAndDeptId(request.getTenantId(),request.getAssetsDeptId());
		}
		List<WxSysUser> wxSysUsers = new ArrayList<WxSysUser>();
		for (SysUser sysUser : sysUsers) {
			//用户被禁用或被删除时不能收到消息提醒
			if(sysUser.getEnable() && !sysUser.getDelFlag()){
				WxSysUser wxSysUser = wxSysUserService.getWxSysUser(sysUser.getId());
				if(null != wxSysUser && wxSysUser.getEnable()){
					wxSysUsers.add(wxSysUser);
				}
			}
		}
		if(wxSysUsers.size() == 0){
			map.put("code", "401");
			map.put("msg", "该机构下拥有"+WeiXinConstants.WEIXIN_REPAIR_MESSAGE_TYPE_MAP.get(request.getType()) + "权限的用户未绑定微信公众号");
			responseMapList.add(map);
			return response(responseMapList);
		}
		logger.debug("########请求内容="+request.toString());
		//维修消息内容
		WeiXinRepairTemplate repairTemplate = new WeiXinRepairTemplate();
		String messageTypeName = WeiXinConstants.WEIXIN_REPAIR_MESSAGE_TYPE_MAP.get(request.getType());
        repairTemplate.setFirst("你有1个维修单需要"+messageTypeName+"，请及时处理");
        repairTemplate.setKeyword1(request.getApplyNo());
        repairTemplate.setKeyword2(request.getAssetsName());
        repairTemplate.setKeyword3(request.getAssetsNum());
        repairTemplate.setKeyword4(request.getAssetsDeptName());
        repairTemplate.setKeyword5(request.getReportRepairName());
        repairTemplate.setRemark("点击登录小程序可在消息中查看");
        logger.debug("########消息内容="+repairTemplate.toString());
    	TreeMap<String, TreeMap<String, String>> messageBody = MapUtils.objectToTreeMap(repairTemplate);
    	logger.debug("########消息体="+messageBody.toString());
    	for (WxSysUser wxSysUser : wxSysUsers) {
    		String openId = wxSysUser.getOpenId();
			Long userId = wxSysUser.getUserId();
			logger.debug("消息接收者userId="+userId);
			logger.debug("消息接收者openId="+openId);
			//消息跳转小程序
	    	Map<String,String> miniprogram = new HashMap<String,String>();
	        miniprogram.put("appid",weiXinConfig.getMiniAppId());
	        miniprogram.put("pagepath", weiXinConfig.getMiniRepairPagePath() + "?openId = " + openId +"&userId = " + userId);
	        TemplateMsgResult templateMsgResult = weiXinService.sendWeiXinMessage(openId, weiXinConfig.getRepairMessageTemplateId(), messageBody, miniprogram);
	        Map<String,Object> responseMap = new HashMap<String,Object>();
	        responseMap.put("userId", String.valueOf(userId));
	        responseMap.put("openId", openId);
	        if(0 == templateMsgResult.getErrcode()){
	        	responseMap.put("code", "200");
	        	responseMap.put("msg", "消息发送成功");
			}else{
				responseMap.put("code", String.valueOf(templateMsgResult.getErrcode()));
				responseMap.put("msg", templateMsgResult.getErrmsg());
			}
	    	responseMapList.add(responseMap);
		}
    	return response(responseMapList);
	}
	
	/**
	 * 发送微信服务平台消息
	 * @return
	 */
	@PostMapping(value = "/weixin/send/service/message")
	@ApiOperation(value = "发送微信服务平台消息", httpMethod = "POST")
	@ApiResponse(code = 0, message = "OK", response = Result.class)
	public Result<List<Map<String, Object>>> sendWeiXinServiceMessage(@RequestBody WeiXinServiceMessageRequest request){
		logger.debug("==============发送微信公众号服务平台消息==============");
		List<Map<String, Object>> responseMapList = new ArrayList<Map<String, Object>>();
		Map<String, Object> map = new HashMap<String, Object>();
		List<Long> tenantIds = request.getTenantIds();
		logger.debug("消息接收者机构ID集合 = " + tenantIds.toString());
		if(null == tenantIds || (null != tenantIds && tenantIds.size() == 0)){
			map.put("code", "401");
			map.put("msg", "机构ID集合不能为空");
			responseMapList.add(map);
			return response(responseMapList);
		}
		List<Long> hospitalTenantIds = new ArrayList<Long>();
		//只有医疗机构下用户才能能接收到消息
		for (Long tenantId : tenantIds) {
			SysTenant sysTenant = systemService.getTenantInfo(tenantId);
			if(null != sysTenant && TenantType.HOSPITAL.getNumber().equals(sysTenant.getTenantType())){
				hospitalTenantIds.add(tenantId);	
			}
		}
		if(hospitalTenantIds.size() == 0){
			map.put("code", "401");
			map.put("msg", "目标医疗机构ID集合为空");
			responseMapList.add(map);
			return response(responseMapList);
		}
		List<SysUser> sysUsers = systemService.getUserByTenantIds(hospitalTenantIds);
		List<WxSysUser> toUsers = new ArrayList<WxSysUser>();
		for (SysUser sysUser : sysUsers) {
			//用户被禁用或被删除时不能收到消息提醒
			if(sysUser.getEnable() && !sysUser.getDelFlag()){
				WxSysUser wxSysUser = wxSysUserService.getWxSysUser(sysUser.getId());
				if(null != wxSysUser && wxSysUser.getEnable()){
					toUsers.add(wxSysUser);
				}
			}
		}
		if(toUsers.size() == 0){
			map.put("code", "401");
			map.put("msg", "所选择的机构用户未绑定微信公众号");
			responseMapList.add(map);
			return response(responseMapList);
		}
		//服务平台消息内容
		WeiXinServiceTemplate weiXinServiceTemplate = new WeiXinServiceTemplate();
		String messageType = WeiXinConstants.WEIXIN_SERVICE_MESSAGE_TYPE_MAP.get(request.getType());
		weiXinServiceTemplate.setFirst("你有1条服务平台"+messageType+"，请及时查看");
		weiXinServiceTemplate.setKeyword1(request.getPublishTenantName());
		weiXinServiceTemplate.setKeyword2(request.getPublishTime());
		weiXinServiceTemplate.setRemark("点击登录小程序可在消息中查看");
		TreeMap<String, TreeMap<String, String>> messageBody = MapUtils.objectToTreeMap(weiXinServiceTemplate);
		for (WxSysUser wxSysUser : toUsers) {
			String openId = wxSysUser.getOpenId();
			Long userId = wxSysUser.getUserId();
			logger.debug("消息接收者userId="+userId);
			logger.debug("消息接收者openId="+openId);
			//消息跳转小程序
	    	Map<String,String> miniprogram = new HashMap<String,String>();
	        miniprogram.put("appid", weiXinConfig.getMiniAppId());
	        miniprogram.put("pagepath", weiXinConfig.getMiniServicePagePath() + "?openId = " + openId +"&userId = " + userId);
	        TemplateMsgResult templateMsgResult = weiXinService.sendWeiXinMessage(openId, weiXinConfig.getServiceMessageTemplateId(), messageBody, miniprogram);
	        Map<String,Object> responseMap = new HashMap<String,Object>();
	        responseMap.put("userId", String.valueOf(userId));
	        responseMap.put("openId", openId);
	        if(0 == templateMsgResult.getErrcode()){
	        	responseMap.put("code", "200");
	        	responseMap.put("msg", "消息发送成功");
			}else{
				responseMap.put("code", String.valueOf(templateMsgResult.getErrcode()));
				responseMap.put("msg", templateMsgResult.getErrmsg());
			}
	    	responseMapList.add(responseMap);
		}
		return response(responseMapList);
	}
	
	/**
     * 小程序我的启用、停用接受公众号消息提醒
     * @param request
     * @param response
     * @return
     */
    @ApiOperation(value = "小程序我的启用、停用接收公众号消息提醒", httpMethod = "GET")
    @ApiResponse(code = 0, message = "OK", response = Result.class)
    @GetMapping(value="/weixin/enableOrDisableReceiveWeChatMessage")
    public Result<Object> enableOrDisableReceiveWeChatMessage(@RequestParam(required = true) Boolean enable,@RequestParam(required = true) Long userId){
        WxSysUser wxSysUser = wxSysUserService.getWxSysUser(userId);
        wxSysUser.setEnable(enable);
        wxSysUserService.updateWxSysUser(wxSysUser);
        return response();
    }
	
}
