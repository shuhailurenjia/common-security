package com.wangzhong.security;

import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;


/**
 * RSA 加密算法，秘钥从文件中读取
 * @author zwh
 * @see CjtRsaPassword
 */
class CjtRsaCoder extends SecretCoderBase {
	
	public static final String NAME = "CJTRSA";

	/** */
	/**
	 * 加密算法RSA
	 */
	public static final String KEY_ALGORITHM = "RSA";

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
		byte[] keyBytes =  SecretUtil.decodeBase64(password);
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key publicK = keyFactory.generatePublic(x509KeySpec);
		// 对数据加密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, publicK);
		byte[] output= cipher.doFinal(plaintext.getBytes());
		
		return  SecretUtil.encodeBase64(output);
	}

	@Override
	protected String innerDecrypt(String password, String ciphertext) throws Exception {
		byte[] keyBytes = SecretUtil.decodeBase64(password);
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, privateK);
		
		byte[] encryptedData = SecretUtil.decodeBase64(ciphertext);
		byte[] decryptedData = cipher.doFinal(encryptedData);
		int length = decryptedData.length;
		
		//使用openssl 加密时只能是文件,同时加密时包含换行符
		if(length > 1 && decryptedData[length-1]== 10){  //换行符
			length = length-1;
		}
		return new String(decryptedData,0,length, CharUtil.UTF8);
	}
	
}
