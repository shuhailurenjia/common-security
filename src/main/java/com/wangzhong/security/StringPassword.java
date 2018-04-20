package com.wangzhong.security;

/**
 * 默认的Password类型,String
 * @author zwh
 *
 */
public class StringPassword implements Password {
	
	protected String passwd ;
	
	public StringPassword(String password) {
		this.passwd = password;
	}
	
	@Override
	public String getPassword() {
		return passwd;
	}

	@Override
	public boolean checkValidate() {
		return true;
	}
}
