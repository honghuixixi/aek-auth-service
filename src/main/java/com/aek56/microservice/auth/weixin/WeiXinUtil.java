package com.aek56.microservice.auth.weixin;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.aek56.microservice.auth.util.MapUtils;
import com.aek56.microservice.auth.weixin.menu.Menu;
import com.aek56.microservice.auth.weixin.message.template.TemplateMsgResult;
import com.aek56.microservice.auth.weixin.message.template.WeiXinTemplateMsg;
import com.aek56.microservice.auth.weixin.token.MyX509TrustManager;
import com.aek56.microservice.auth.weixin.token.WeiXinJsCode2Session;
import com.aek56.microservice.auth.weixin.token.WeiXinOauth2Token;
import com.aek56.microservice.auth.weixin.userinfo.SNSUserInfo;
import com.aek56.microservice.auth.weixin.userinfo.WeiXinUserInfo;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONException;
import com.alibaba.fastjson.JSONObject;

/**
 * 微信Token工具类
 *	
 * @author HongHui
 * @date   2017年12月1日
 */
public class WeiXinUtil {
	
	private static final Log logger = LogFactory.getLog(WeiXinUtil.class);
	
	/**
	 * 发送模板消息(POST)
	 */
	public static String POST_SEND_TEMPLATE_MSG_URL = "https://api.weixin.qq.com/cgi-bin/message/template/send?access_token=ACCESS_TOKEN";
	
	/**
	 * 创建自定义菜单
	 * @param menu
	 * @param accessToken
	 * @return
	 */
	public static int createMenu(String url,Menu menu,String accessToken){
		int result = 0;
        // 拼装创建菜单的url
        url = url.replace("ACCESS_TOKEN", accessToken);                           
        // 将菜单对象转换成json字符串
        String jsonMenu = JSONObject.toJSONString(menu);
        // 调用接口创建菜单
        JSONObject jsonObject = httpsRequestJson(url, "POST", jsonMenu);
        if (null != jsonObject) {
        	if(0 != jsonObject.getIntValue("errcode")){
        		result = jsonObject.getIntValue("errcode");
                logger.debug("创建菜单失败 errcode:"+jsonObject.getIntValue("errcode")+" errmsg:"+jsonObject.getString("errmsg"));
        	}
        }
        return result;
	} 
	
	/**
	 * 获取微信用户基本信息
	 * @param accessToken
	 * @param openId
	 * @return
	 */
	public static WeiXinUserInfo getWeiXinUserInfo(String requestUrl,String accessToken,String openId){
		WeiXinUserInfo weixinUserInfo = null;
        requestUrl = requestUrl.replace("ACCESS_TOKEN", accessToken).replace("OPENID", openId);
        // 获取用户信息
        JSONObject jsonObject = httpsRequestJson(requestUrl, "GET", null);
        System.out.println(jsonObject.toJSONString());
        if(null != jsonObject){
        	try {
                weixinUserInfo = new WeiXinUserInfo();
                // 用户的标识
                weixinUserInfo.setOpenId(jsonObject.getString("openid"));
                // 关注状态（1是关注，0是未关注），未关注时获取不到其余信息
                weixinUserInfo.setSubscribe(jsonObject.getIntValue("subscribe"));
                // 用户关注时间
                weixinUserInfo.setSubscribeTime(jsonObject.getString("subscribe_time"));
                // 昵称
                weixinUserInfo.setNickname(jsonObject.getString("nickname"));
                // 用户的性别（1是男性，2是女性，0是未知）
                weixinUserInfo.setSex(jsonObject.getIntValue("sex"));
                // 用户所在国家
                weixinUserInfo.setCountry(jsonObject.getString("country"));
                // 用户所在省份
                weixinUserInfo.setProvince(jsonObject.getString("province"));
                // 用户所在城市
                weixinUserInfo.setCity(jsonObject.getString("city"));
                // 用户的语言，简体中文为zh_CN
                weixinUserInfo.setLanguage(jsonObject.getString("language"));
                // 用户头像
                weixinUserInfo.setHeadImgUrl(jsonObject.getString("headimgurl"));
            } catch (Exception e) {
                if (0 == weixinUserInfo.getSubscribe()) {
                    logger.debug("用户"+weixinUserInfo.getOpenId()+"已取消关注");
                } else {
                    int errorCode = jsonObject.getIntValue("errcode");
                    String errorMsg = jsonObject.getString("errmsg");
                    logger.debug("获取用户信息失败 errcode:"+errorCode+" errmsg:" + errorMsg);
                }
            }
        }
		return weixinUserInfo;
	}
	
	/**
	 * 获取网页授权凭证
	 * @param appId
	 * @param appSecret
	 * @param code
	 * @return
	 */
	public static WeiXinOauth2Token getOauth2AccessToken(String requestUrl,String appId, String appSecret, String code){
		WeiXinOauth2Token wat = null;
        // 拼接请求地址
        requestUrl = requestUrl.replace("APPID", appId);
        requestUrl = requestUrl.replace("SECRET", appSecret);
        requestUrl = requestUrl.replace("CODE", code);
        // 获取网页授权凭证
        JSONObject jsonObject = httpsRequestJson(requestUrl, "GET", null);
        if (null != jsonObject) {
            try {
                wat = new WeiXinOauth2Token();
                wat.setAccessToken(jsonObject.getString("access_token"));
                wat.setExpiresIn(jsonObject.getIntValue("expires_in"));
                wat.setRefreshToken(jsonObject.getString("refresh_token"));
                wat.setOpenId(jsonObject.getString("openid"));
                wat.setScope(jsonObject.getString("scope"));
            } catch (Exception e) {
            	e.printStackTrace();
                wat = null;
                int errorCode = jsonObject.getIntValue("errcode");
                String errorMsg = jsonObject.getString("errmsg");
                logger.debug("获取网页授权凭证失败 errcode:"+errorCode+" errmsg:" + errorMsg);
            }
        }
        return wat;
	}
	
	/**
	 * 获取网页授权凭证
	 * @param appId
	 * @param appSecret
	 * @param code
	 * @return
	 */
	public static WeiXinJsCode2Session getJsCode2Session(String requestUrl,String appId, String appSecret, String code){
		WeiXinJsCode2Session weiXinJsCode2Session = null;
        // 拼接请求地址
        requestUrl = requestUrl.replace("APPID", appId);
        requestUrl = requestUrl.replace("SECRET", appSecret);
        requestUrl = requestUrl.replace("JSCODE", code);
        // 获取网页授权凭证
        JSONObject jsonObject = httpsRequestJson(requestUrl, "GET", null);
        if (null != jsonObject) {
            try {
            	weiXinJsCode2Session = new WeiXinJsCode2Session();
            	weiXinJsCode2Session.setOpenId(jsonObject.getString("openid"));
            	weiXinJsCode2Session.setSession_key(jsonObject.getString("session_key"));
            	weiXinJsCode2Session.setUnionid(jsonObject.getString("unionid"));
            } catch (Exception e) {
            	e.printStackTrace();
            	weiXinJsCode2Session = null;
                int errorCode = jsonObject.getIntValue("errcode");
                String errorMsg = jsonObject.getString("errmsg");
                logger.debug("获取网页授权凭证失败 errcode:"+errorCode+" errmsg:" + errorMsg);
            }
        }
        return weiXinJsCode2Session;
	}
	
	/**
	 * 通过网页授权获取用户信息
	 * @param accessToken
	 * @param openId
	 * @return
	 */
	public static SNSUserInfo getSNSUserInfo(String requestUrl,String accessToken, String openId){
		SNSUserInfo snsUserInfo = null;
        requestUrl = requestUrl.replace("ACCESS_TOKEN", accessToken).replace("OPENID", openId);
        // 通过网页授权获取用户信息
        JSONObject jsonObject = httpsRequestJson(requestUrl, "GET", null);
        if (null != jsonObject) {
            try {
                snsUserInfo = new SNSUserInfo();
                // 用户的标识
                snsUserInfo.setOpenId(jsonObject.getString("openid"));
                // 昵称
                snsUserInfo.setNickname(jsonObject.getString("nickname"));
                // 性别（1是男性，2是女性，0是未知）
                snsUserInfo.setSex(jsonObject.getIntValue("sex"));
                // 用户所在国家
                snsUserInfo.setCountry(jsonObject.getString("country"));
                // 用户所在省份
                snsUserInfo.setProvince(jsonObject.getString("province"));
                // 用户所在城市
                snsUserInfo.setCity(jsonObject.getString("city"));
                // 用户头像
                snsUserInfo.setHeadImgUrl(jsonObject.getString("headimgurl"));
                // 用户特权信息
                snsUserInfo.setPrivilegeList(JSONArray.parseArray(jsonObject.getString("privilege"),String.class));
                //只有在用户将公众号绑定到微信开放平台帐号后，才会出现该字段
                snsUserInfo.setUnionId(jsonObject.getString("unionid"));
            } catch (Exception e) {
                snsUserInfo = null;
                int errorCode = jsonObject.getIntValue("errcode");
                String errorMsg = jsonObject.getString("errmsg");
                logger.debug("获取用户信息失败 errcode:"+errorCode+" errmsg:" + errorMsg);
            }
        }
        return snsUserInfo;
	}
	
	/**
	 * 根据CODE获取OpenId
	 * @param code
	 * @return
	 */
	public static String getOpenId(String requestUrl,String appId,String appSecret,String code){
		String openId = null;
		requestUrl = requestUrl.replace("APPID", appId).replace("APPSECRET", appSecret).replace("CODE", code);
		JSONObject jsonObject = httpsRequestJson(requestUrl, "GET", null);
		if(null != jsonObject){
			try {
				openId = jsonObject.getString("openid");
            } catch (JSONException e) {
            	openId = null;
                // 获取openid失败
                logger.error("获取openid失败 errcode:"+jsonObject.getIntValue("errcode")+" errmsg:"+jsonObject.getString("errmsg"));
            }
		}
		return openId;
	}
	
	/**
	 * 发送模板消息
	 * @param accessToken
	 * @param data
	 * @return
	 */
	public static TemplateMsgResult sendWeiXinTemplateMsg(String requestUrl,String accessToken, String data) {  
        TreeMap<String,String> params = new TreeMap<String,String>();  
        params.put("access_token", accessToken);  
        requestUrl = requestUrl.replace("ACCESS_TOKEN", accessToken);
        JSONObject jsonObject = httpsRequestJson(requestUrl, "POST", data);
        TemplateMsgResult templateMsgResult = jsonObject.toJavaObject(TemplateMsgResult.class);
        return templateMsgResult;
	}
	
	/**
	 * 获取微信凭证字符信息
	 * @param requestUrl
	 * @param requestMethod
	 * @param outputStr
	 * @return
	 */
	public static String httpsRequest(String requestUrl , String requestMethod , String outputStr) {
        StringBuffer buffer = new StringBuffer();
        try {
            // 创建SSLContext对象，并使用我们指定的信任管理器初始化
            TrustManager[] tm = { new MyX509TrustManager() };
            SSLContext sslContext = SSLContext.getInstance("SSL" , "SunJSSE");
            sslContext.init(null , tm , new java.security.SecureRandom());
            // 从上述SSLContext对象中得到SSLSocketFactory对象
            SSLSocketFactory ssf = sslContext.getSocketFactory();

            URL url = new URL(requestUrl);
            HttpsURLConnection httpUrlConn = (HttpsURLConnection) url.openConnection();
            httpUrlConn.setSSLSocketFactory(ssf);

            httpUrlConn.setDoOutput(true);
            httpUrlConn.setDoInput(true);
            httpUrlConn.setUseCaches(false);
            // 设置请求方式(GET/POST)
            httpUrlConn.setRequestMethod(requestMethod);
            if ("GET".equalsIgnoreCase(requestMethod)) httpUrlConn.connect();
            // 当有数据需要提交时
            if (null != outputStr) {
                OutputStream outputStream = httpUrlConn.getOutputStream();
                // 注意编码格式，防止中文乱码
                outputStream.write(outputStr.getBytes("UTF-8"));
                outputStream.close();
            }

            // 将返回的输入流转换成字符串
            InputStream inputStream = httpUrlConn.getInputStream();
            InputStreamReader inputStreamReader = new InputStreamReader(inputStream , "UTF-8");
            BufferedReader bufferedReader = new BufferedReader(inputStreamReader);

            String str = null;
            while ((str = bufferedReader.readLine()) != null) {
                buffer.append(str);
            }
            bufferedReader.close();
            inputStreamReader.close();
            // 释放资源
            inputStream.close();
            inputStream = null;
            httpUrlConn.disconnect();
            return buffer.toString();
        } catch (ConnectException ce) {
        	ce.printStackTrace();
            logger.info("Weixin server connection timed out.......");
        } catch (Exception e) {
        	e.printStackTrace();
        	logger.info("Error.......");
        }
        return buffer.toString();
    }
	
	/**
	 * 获取微信凭证字符信息
	 * @param requestUrl
	 * @param requestMethod
	 * @param outputStr
	 * @return
	 */
	public static JSONObject httpsRequestJson(String requestUrl, String requestMethod, String outputStr) {
        JSONObject jsonObject = null;
        StringBuffer buffer = new StringBuffer();
        try {
            // 创建SSLContext对象，并使用我们指定的信任管理器初始化
            TrustManager[] tm = { new MyX509TrustManager() };
            SSLContext sslContext = SSLContext.getInstance("SSL", "SunJSSE");
            sslContext.init(null, tm, new java.security.SecureRandom());
            // 从上述SSLContext对象中得到SSLSocketFactory对象
            SSLSocketFactory ssf = sslContext.getSocketFactory();

            URL url = new URL(requestUrl);
            HttpsURLConnection httpUrlConn = (HttpsURLConnection) url.openConnection();
            httpUrlConn.setSSLSocketFactory(ssf);

            httpUrlConn.setDoOutput(true);
            httpUrlConn.setDoInput(true);
            httpUrlConn.setUseCaches(false);
            
            // 设置请求方式（GET/POST）
            httpUrlConn.setRequestMethod(requestMethod);

            if ("GET".equalsIgnoreCase(requestMethod))
                httpUrlConn.connect();

            // 当有数据需要提交时
            if (null != outputStr) {
                OutputStream outputStream = httpUrlConn.getOutputStream();
                // 注意编码格式，防止中文乱码
                outputStream.write(outputStr.getBytes("UTF-8"));
                outputStream.close();
            }

            // 将返回的输入流转换成字符串
            InputStream inputStream = httpUrlConn.getInputStream();
            InputStreamReader inputStreamReader = new InputStreamReader(inputStream, "utf-8");
            BufferedReader bufferedReader = new BufferedReader(inputStreamReader);

            String str = null;
            while ((str = bufferedReader.readLine()) != null) {
                buffer.append(str);
            }
            bufferedReader.close();
            inputStreamReader.close();
            // 释放资源
            inputStream.close();
            inputStream = null;
            httpUrlConn.disconnect();
            jsonObject = JSONObject.parseObject(buffer.toString());
        } catch (ConnectException ce) {
            logger.error("Weixin server connection timed out.");
        } catch (Exception e) {
        	logger.error("https request error:{}", e);
        }
        return jsonObject;
    }
	
	public static void main(String[] args) {
		//Token token = WeiXinUtil.getAccessToken(WeiXinConstants.APPID, WeiXinConstants.APPSECRET);
		//System.out.println("access_token = "+token.getAccess_token());
		/*String access_token = "OIZB5-s1q5bo3d8TPs_rYd7yR0mEe21KBgjMFxLkPuf_UAmf9Us8U24ynSbq1_FWWcAQ41ct-3RDHrcQgHbyzOqAE91oJ6Q8KTkYbe9vJAqdPdiBonXGZvojxqYIdTRINTAhAJAZFM";
		WeiXinUserInfo userInfo = WeiXinUtil.getWeiXinUserInfo(access_token, "oPe9c0Y0SLb_2w4vAqjsLqYQWmiE");
		if(null != userInfo){
			System.out.println(userInfo.toString());
		}else{
			System.out.println("返回数据为空");
		}*/
		String accessToken = "nFtAVLq7bABlTABlPeSNAmbVGj-OiZrYeRaFalXJQZoMjWEEkXzLY23Gw3GnHfAbWYBiN2HwzeJGoUd-u4UDHRDtI_Ur_d38jHOWqLr5EDOYU70ox_BH0CBFzTd-9FcLRNGfAAAXTM";
		TemplateMsgResult templateMsgResult = null;  
        
        /*WeiXinRepairTemplate repairTemplate = new WeiXinRepairTemplate();
        repairTemplate.setType(3);
        String messageTypeName = WeiXinConstants.WEIXIN_REPAIR_MESSAGE_TYPE_MAP.get(3);
        repairTemplate.setTitle("你有1个维修单需要"+messageTypeName+"，请及时处理");
        repairTemplate.setApplyId(1l);
        repairTemplate.setApplyNo("WX20171121774760");
        repairTemplate.setAssetsName("脉动真空灭火器");
        repairTemplate.setAssetsNum("H00000120171130000530");
        repairTemplate.setAssetsDeptId(1L);
        repairTemplate.setAssetsDeptName("设备科");
        repairTemplate.setReportRepairId(1l);
        repairTemplate.setReportRepairName("张三");
        repairTemplate.setRemark("点击登录小程序可在消息中查看");*/
       
         

    	/*TreeMap<String, TreeMap<String, String>> params = MapUtils.objectToTreeMap(repairTemplate);
        
        System.out.println(params.toString());
        WeiXinTemplateMsg wechatTemplateMsg = new WeiXinTemplateMsg();  
        wechatTemplateMsg.setTemplate_id("QljNIv-OyzZpcN8TONYTCF_oYuyFUK5x041NXm2AdhY");    
        wechatTemplateMsg.setTouser("oPe9c0Y0SLb_2w4vAqjsLqYQWmiE");  
        wechatTemplateMsg.setUrl("http://music.163.com/#/song?id=27867140");  
        wechatTemplateMsg.setData(params);  
        Map<String,String> miniprogram = new HashMap<String,String>();
        miniprogram.put("appid", "wxee5957e2cc752628");
        miniprogram.put("pagepath", "pages/workplat/workplat?openId=oPe9c0Y0SLb_2w4vAqjsLqYQWmiE");
        //wechatTemplateMsg.setMiniprogram(miniprogram);
        String data = JSON.toJSONString(wechatTemplateMsg);
        System.out.println(data);
        templateMsgResult =  WeiXinUtil.sendWeiXinTemplateMsg(POST_SEND_TEMPLATE_MSG_URL,accessToken, data); 
        System.out.println(templateMsgResult.toString());*/
	}
}
