package com.wangzhong.security;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * <p>
 * AES对称加密算法
 * </p>
 * 
 * @author zwh
 */
final class AESCoder extends SecretCoderBase {

	// 盐初始化，暂不进行随机处理
	private static final byte[] SALT = "0000000000201517".getBytes();

	public static final String NAME = "AES";

	/*
	 * (non-Javadoc)
	 * 
	 */
	@Override
	protected String getName() {
		return NAME;
	}

	/*
	 * (non-Javadoc)
	 * 
	 */
	@Override
	protected String getAlgorithm() {
		// 加密算法/加密模式/填充方式 ，如果不填充，则对明文长度有要求
		return "AES/CBC/PKCS5Padding";
	}

	@Override
	protected String innerEncrypt(String password, String plaintext) throws Exception {
		check(password, plaintext);
		byte[] raw = password.getBytes(CharUtil.UTF8);
		SecretKeySpec skeySpec = new SecretKeySpec(raw, getName());
		Cipher cipher = Cipher.getInstance(getAlgorithm());
		IvParameterSpec iv = new IvParameterSpec(SALT);
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
		byte[] encrypted = cipher.doFinal(plaintext.getBytes(CharUtil.UTF8));
		return SecretUtil.byte2hex(encrypted);
	}

	@Override
	protected String innerDecrypt(String password, String ciphertext) throws Exception {
		check(password, ciphertext);
		byte[] raw = password.getBytes(CharUtil.UTF8);
		SecretKeySpec skeySpec = new SecretKeySpec(raw, getName());
		Cipher cipher = Cipher.getInstance(getAlgorithm());
		IvParameterSpec iv = new IvParameterSpec(SALT);
		cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
		byte[] encrypted1 = SecretUtil.hex2byte(ciphertext);
		byte[] original = cipher.doFinal(encrypted1);
		String originalString = new String(original, CharUtil.UTF8);
		return originalString;
	}

	private void check(String password, String text) throws SecretException {
		if (password.length() != 16) { // 16,24,32
			throw new SecretException("password length should be 16");
		}
	}

}
