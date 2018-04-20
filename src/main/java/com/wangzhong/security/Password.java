package com.wangzhong.security;

/**
 * 密码接口
 * @author zwh
 *
 */
public interface Password {
	/**
	 * 获取秘钥
	 * @return
	 */
	String getPassword();
	
	/**
	 * 检查秘钥是否正常
	 * @return
	 */
	boolean checkValidate();
}
