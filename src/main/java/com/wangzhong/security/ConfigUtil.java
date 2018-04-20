package com.wangzhong.security;

/**
 * 配置工具类
 * @author zwh
 *
 */
public class ConfigUtil {
	
	/**
	 * 获取默认的配置
	 * @param key
	 * @param defaultStr
	 * @return
	 */
	public static String getEnvValue(String key, String defaultStr) {
		String value = System.getProperty(key);
		if (value != null) {
			defaultStr = value;
		}
		return defaultStr;
	}
	
	/**
	 * 获取秘钥文件默认路径:  ~/.ssh/search_pri_sign_key.pem <br/>
	 * 可以通过的JVM启动参数进行设置  -DsearchPriKey=/path/of/signkeyname
	 * @return
	 */
//	public static String getDefaultKeyPath() {
//		return getEnvValue("searchPriKey", getEnvValue("user.home", "/root") + "/.ssh/search_pri_sign_key.pem");
//	}	

}
