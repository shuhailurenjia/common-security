package com.wangzhong.security;

import java.security.Key;

import javax.crypto.Cipher;

/**
 * <p>
 * RSA非对称加密算法
 * </p>
 * 
 * @author zwh
 */
final class RSACoder extends SecretCoderBase {

	public static final String NAME = "RSA";

	@Override
	protected String getName() {
		return NAME;
	}

	@Override
	protected String getAlgorithm() {
		return "RSA";
	}

	@Override
	protected String innerEncrypt(String password, String plaintext) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		// 得到Key
		Key key = decodeKey(password);
		// 加密
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] bytes = cipher.doFinal(plaintext.getBytes(CharUtil.UTF8));
		// 构造返回数据，需要base64编码
		String ciphertext = SecretUtil.encodeBase64(bytes);
		return ciphertext;
	}

	@Override
	protected String innerDecrypt(String password, String ciphertext) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		// 得到Key
		Key key = decodeKey(password);
		// 解密
		cipher.init(Cipher.DECRYPT_MODE, key);
		// 需要base64解码
		byte[] bytes = SecretUtil.decodeBase64(ciphertext);
		byte[] result = cipher.doFinal(bytes);
		// 构造返回数据
		String plaintext = new String(result, CharUtil.UTF8);
		return plaintext;
	}

}
