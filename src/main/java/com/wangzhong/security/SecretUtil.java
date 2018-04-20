package com.wangzhong.security;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

import org.apache.commons.codec.binary.Base64;

/**
 * <p>
 * 安全相关的工具类
 * </p>
 * 
 * @author zwh
 * @Email zwh@chanjet.com
 * @date 2014年3月13日 上午11:25:57
 * @version V1.0
 */
public final class SecretUtil {

	/**
	 * PBE加密算法，对密码长度和明文长度无要求
	 */
	public static final String PBE = PBECoder.NAME;
	/**
	 * AES加密算法，要求密码长度16，明文长度是16的倍数
	 */
	public static final String AES = AESCoder.NAME;
	/**
	 * RSA加密算法,秘钥Java生成的秘钥对
	 */
	public static final String RSA = RSACoder.NAME;
	/**
	 * CJT RSA加密算法,秘钥为PEM，包含签名验证
	 */
	public static final String CJTRSA = CjtRsaCoder.NAME;

	// 加密器
	private static HashMap<String, SecretCoder> coders;

	static {
		coders = new HashMap<String, SecretCoder>();
		coders.put(PBECoder.NAME, new PBECoder());
		coders.put(AESCoder.NAME, new AESCoder());
		coders.put(RSACoder.NAME, new RSACoder());
		coders.put(CjtRsaCoder.NAME, new CjtRsaCoder());
	}

	/**
	 * 
	 * <p>
	 * 对称加密
	 * </p>
	 * 
	 * @param algorithm
	 *            加密算法 SecretUtil.PBE ...
	 * @param password
	 *            密码
	 * @param plaintext
	 *            明文
	 * @return 密文
	 * @throws SecretException
	 * @throws PlatformException
	 */
	public static String encrypt(String algorithm, String password, String plaintext) throws SecretException {
		if (SecretUtil.CJTRSA.equals(algorithm)) {
			throw new SecretException(algorithm + "不支持秘钥字符串传入");
		}
		SecretCoder coder = getCoder(algorithm);
		return coder.encrypt(password, plaintext);
	}

	public static String encrypt(String algorithm, Password password, String plaintext) throws SecretException {
		SecretCoder coder = getCoder(algorithm);
		return coder.encrypt(password, plaintext);
	}

	/**
	 * 
	 * <p>
	 * 对称解密
	 * </p>
	 * 
	 * @param algorithm
	 *            加密算法 SecretUtil.PBE ...
	 * @param password
	 *            密码
	 * @param ciphertext
	 *            密文
	 * @return 明文
	 * @throws SecretException
	 */
	public static String decrypt(String algorithm, String password, String ciphertext) throws SecretException {
		if (SecretUtil.CJTRSA.equals(algorithm)) {
			throw new SecretException(algorithm + "不支持秘钥字符串传入");
		}
		SecretCoder coder = getCoder(algorithm);
		return coder.decrypt(password, ciphertext);
	}

	/**
	 * 
	 * @param algorithm
	 * @param password
	 * @param ciphertext
	 * @return
	 * @throws SecretException
	 */
	public static String decrypt(String algorithm, Password password, String ciphertext) throws SecretException {
		SecretCoder coder = getCoder(algorithm);
		return coder.decrypt(password, ciphertext);
	}

	private static SecretCoder getCoder(String algorithm) throws SecretException {
		SecretCoder coder = coders.get(algorithm);
		if (coder == null) {
			throw new SecretException("unsupport secret algorithm:" + algorithm);
		}
		return coder;
	}

	/**
	 * 
	 * <p>
	 * 产生密钥 非对称加密算法，数组第一个元素是公钥，第二个元素是私钥
	 * </p>
	 * 
	 * @param algorithm
	 * @return
	 * @throws SecretException
	 * @throws NoSuchAlgorithmException
	 */
	public static String[] generateKeyPair(String algorithm) throws SecretException, NoSuchAlgorithmException {
		// 实例化Key
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
		// 获取一对钥匙
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		// 获得公钥
		String publicKey = RSACoder.encodeKey(keyPair.getPublic());
		// 获得私钥
		String privateKey = RSACoder.encodeKey(keyPair.getPrivate());
		return new String[] { publicKey, privateKey };
	}

	/**
	 * 
	 * <p>
	 * 获取字符串的MD5编码
	 * </p>
	 * 
	 * @param str
	 * @return
	 * 
	 * @author : zwh
	 * @date : 2014年3月13日
	 */
	public static String hexMD5(String str) {
		try {
			// 生成一个MD5加密计算摘要
			MessageDigest md = MessageDigest.getInstance("MD5");
			// 计算md5函数
			md.update(str.getBytes(CharUtil.UTF8));
			// digest()最后确定返回md5 hash值，返回值为8为字符串。因为md5 hash值是16位的hex值，实际上就是8位的字符
			// BigInteger函数则将8位的字符串转换成16位hex值，用字符串来表示；得到字符串形式的hash值
			String md5 = new BigInteger(1, md.digest()).toString(16);
			return md5;
		} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			throw new RuntimeException(str, e);
		}
	}

	/**
	 * 
	 * <p>
	 * 将原始数据编码为base64编码
	 * </p>
	 * 
	 * @param data
	 *            原始数据
	 * @return base64编码
	 */
	static String encodeBase64(byte[] data) {
		byte[] out = Base64.encodeBase64(data);
		return new String(out);
	}

	/**
	 * 
	 * <p>
	 * 将base64编码的数据解码成原始数据
	 * </p>
	 * 
	 * @param data
	 *            base64编码
	 * @return 原始数据
	 */
	static byte[] decodeBase64(String data) {
		byte[] out = Base64.decodeBase64(data);
		return out;
	}

	/**
	 * 
	 * <p>
	 * 将byte转换为16进制
	 * </p>
	 * 
	 * @param bytes
	 * @return 16进制
	 */
	static String byte2hex(byte[] bytes) {
		StringBuilder hs = new StringBuilder();
		String stmp = "";
		for (int n = 0; n < bytes.length; n++) {
			stmp = (java.lang.Integer.toHexString(bytes[n] & 0XFF));
			if (stmp.length() == 1) {
				hs.append("0").append(stmp);
			} else {
				hs.append(stmp);
			}
		}
		return hs.toString().toUpperCase();
	}

	/**
	 * 
	 * <p>
	 * 将16进制转换为bytes
	 * </p>
	 * 
	 * @param hex
	 * @return bytes
	 */
	static byte[] hex2byte(String hex) {
		if (hex == null) {
			return null;
		}
		int l = hex.length();
		if ((l & 1) == 1) {
			return null;
		}
		byte[] b = new byte[l / 2];
		for (int i = 0; i != l / 2; i++) {
			b[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
		}
		return b;
	}

}
