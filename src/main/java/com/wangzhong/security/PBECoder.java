package com.wangzhong.security;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * <p>
 * PBE对称加密算法 基于用户密码和随机数（盐）的简便加密方式
 * </p>
 * 
 * @author zwh
 */
final class PBECoder extends SecretCoderBase {

	// 盐初始化，暂不进行随机处理
	private static final byte[] SALT = "20150107".getBytes();

	public static final String NAME = "PBE";

	@Override
	protected String getName() {
		return NAME;
	}

	@Override
	protected String getAlgorithm() {
		return "PBEWITHMD5andDES";
	}

	@Override
	protected String innerEncrypt(String password, String plaintext) throws Exception {
		// 根据密码创建密钥
		Key key = generateKey(password);
		// 加密
		PBEParameterSpec paramSpec = new PBEParameterSpec(SALT, 100);
		Cipher cipher = Cipher.getInstance(getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
		byte[] result = cipher.doFinal(plaintext.getBytes(CharUtil.UTF8));
		// 返回数据
		String ciphertext = SecretUtil.encodeBase64(result);
		return ciphertext;
	}

	@Override
	protected String innerDecrypt(String password, String ciphertext) throws Exception {
		// 根据密码创建密钥
		Key key = generateKey(password);
		// 解密
		PBEParameterSpec paramSpec = new PBEParameterSpec(SALT, 100);
		Cipher cipher = Cipher.getInstance(getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
		byte[] result = cipher.doFinal(SecretUtil.decodeBase64(ciphertext));
		// 返回数据
		String plaintext = new String(result, CharUtil.UTF8);
		return plaintext;
	}

	/**
	 * 
	 * <p>
	 * 根据口令产生密钥
	 * </p>
	 * 
	 * @param password
	 * @return
	 * @throws PlatformException
	 */
	private Key generateKey(String password) throws SecretException {
		try {
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(getName());
			PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
			SecretKey secretKey = keyFactory.generateSecret(keySpec);
			return secretKey;
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new SecretException("generate Key from password failed.", e);
		}
	}

}
