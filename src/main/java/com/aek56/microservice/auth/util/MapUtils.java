package com.aek56.microservice.auth.util;

import java.beans.BeanInfo;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

import com.aek56.microservice.auth.weixin.WeiXinConstants;
import com.aek56.microservice.auth.weixin.message.template.WeiXinRepairTemplate;

/**
 * 工具类
 *	
 * @author HongHui
 * @date   2017年12月7日
 */
public class MapUtils {
  
	/**
	 * Map转Object
	 * @param map
	 * @param beanClass
	 * @return
	 * @throws Exception
	 */
    public static Object mapToObject(Map<String, Object> map, Class<?> beanClass) throws Exception {    
        if (map == null)   
            return null;    
  
        Object obj = beanClass.newInstance();  
  
        BeanInfo beanInfo = Introspector.getBeanInfo(obj.getClass());    
        PropertyDescriptor[] propertyDescriptors = beanInfo.getPropertyDescriptors();    
        for (PropertyDescriptor property : propertyDescriptors) {  
            Method setter = property.getWriteMethod();    
            if (setter != null) {  
                setter.invoke(obj, map.get(property.getName()));   
            }  
        }  
  
        return obj;  
    }    
      
    /**
     * Object装Map
     * @param obj
     * @return
     * @throws Exception
     */
    public static Map<String, Object> objectToMap(Object obj) throws Exception {    
        if(obj == null)  
            return null;      
  
        Map<String, Object> map = new HashMap<String, Object>();   
  
        BeanInfo beanInfo = Introspector.getBeanInfo(obj.getClass());    
        PropertyDescriptor[] propertyDescriptors = beanInfo.getPropertyDescriptors();    
        for (PropertyDescriptor property : propertyDescriptors) {    
            String key = property.getName();    
            if (key.compareToIgnoreCase("class") == 0) {   
                continue;  
            }  
            Method getter = property.getReadMethod();  
            Object value = getter!=null ? getter.invoke(obj) : null;  
            map.put(key, value);  
        }    
  
        return map;  
    }    
  
    /**
     * Object转为TreeMap
     * @param obj
     * @return
     * @throws Exception
     */
    public static TreeMap<String, TreeMap<String, String>> objectToTreeMap(Object obj){
    	try{
	        if(obj == null)  
	            return null;      
	        TreeMap<String, TreeMap<String, String>> map = new TreeMap<String, TreeMap<String, String>>();   
	        BeanInfo beanInfo = Introspector.getBeanInfo(obj.getClass());    
	        PropertyDescriptor[] propertyDescriptors = beanInfo.getPropertyDescriptors();    
	        for (PropertyDescriptor property : propertyDescriptors) {    
	            String key = property.getName();    
	            if (key.compareToIgnoreCase("class") == 0) {   
	                continue;  
	            }  
	            Method getter = property.getReadMethod();  
	            Object value = getter!=null ? getter.invoke(obj) : null;  
	            TreeMap<String, String> params = new TreeMap<String, String>();
	            params.put("value", value == null ? null : value.toString());  
	            params.put("color", "#000000");  
	            map.put(key, params);  
	        }    
	        return map;  
    	}catch(Exception e){
    		e.printStackTrace();
    	}
    	return null;
    }
    
    public static void main(String[] args) {
    	WeiXinRepairTemplate repairTemplate = new WeiXinRepairTemplate();
		String messageTypeName = WeiXinConstants.WEIXIN_REPAIR_MESSAGE_TYPE_MAP.get(2);
        repairTemplate.setFirst("你有1个维修单需要"+messageTypeName+"，请及时处理");
        repairTemplate.setKeyword1("WX20180316230497");
        repairTemplate.setKeyword2("上海市");
        repairTemplate.setKeyword3(null);
        repairTemplate.setKeyword4("国际庄钢铁集团医院【测试用】");
        repairTemplate.setKeyword5("王大锤不开会糊涂啦说谁是狗");
        repairTemplate.setRemark("点击登录小程序可在消息中查看");
    	TreeMap<String, TreeMap<String, String>> messageBody = MapUtils.objectToTreeMap(repairTemplate);
    	System.out.println(messageBody.toString());
	}
}
