package com.wangzhong.security;

import java.io.IOException;
import java.io.InputStream;

/**
 * openssl 生成的对应一组秘钥<br/>
 * -----BEGIN RSA PRIVATE KEY-----
 * -----END PUBLIC KEY-----
 * @author zwh
 *
 */
class RsaPassword extends StringPassword {

	public RsaPassword(String password) {
		super(password);
	}
	
	public RsaPassword(InputStream is) throws IOException {
		super("");
		String content = FilePassword.read(is);
		this.passwd = content;
	}
	
	@Override
	public String getPassword() {
		return getRawKeys(passwd);
	}
	
	/**
	 * 去除秘钥的注释部分
	 * @param keyContent
	 * @return
	 */
	public static String getRawKeys(String keyContent) {
		if (keyContent != null) {
			String[] arrs = keyContent.split("\n");
			StringBuilder sb = new StringBuilder();
			for (int idx = 0; idx < arrs.length; idx++) {
				String tmp = arrs[idx].trim();
				if (!tmp.startsWith("-")) {
					sb.append(tmp);
				}
			}
			return sb.toString();
		}
		return null;
	}
}
