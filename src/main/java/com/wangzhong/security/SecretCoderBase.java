package com.wangzhong.security;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;

/**
 * <p>
 * 加解密基类
 * </p>
 * 
 * @author zwh
 */
abstract class SecretCoderBase implements SecretCoder {

	@Override
	public String encrypt(String password, String plaintext) throws SecretException {
		if (password == null) {
			throw new SecretException("password is null");
		}
		if (plaintext == null) {
			throw new SecretException("plaintext is null");
		}
		try {
			return innerEncrypt(password, plaintext);
		} catch (Exception e) {
			throw new SecretException("encrypt by " + this.getName() + " failed.", e);
		}
	}

	@Override
	public String decrypt(String password, String ciphertext) throws SecretException {
		try {
			return innerDecrypt(password, ciphertext);
		} catch (Exception e) {
			throw new SecretException("decrypt by " + this.getName() + " failed.", e);
		}
	}

	/**
	 * 
	 * <p>
	 * 获取加密器的名称
	 * </p>
	 * 
	 * @return 加密算法的名称
	 */
	protected abstract String getName();

	/**
	 * 
	 * <p>
	 * 获取加密算法
	 * </p>
	 * 
	 * @return 加密算法
	 */
	protected abstract String getAlgorithm();

	/**
	 * 
	 * <p>
	 * 加密
	 * </p>
	 * 
	 * @param password
	 *            密码
	 * @param plaintext
	 *            明文
	 * @return 密文
	 * @throws Exception
	 */
	protected abstract String innerEncrypt(String password, String plaintext) throws Exception;

	/**
	 * 
	 * <p>
	 * 解密
	 * </p>
	 * 
	 * @param password
	 *            密码
	 * @param ciphertext
	 *            密文
	 * @return 明文
	 * @throws Exception
	 */
	protected abstract String innerDecrypt(String password, String ciphertext) throws Exception;

	/**
	 * 
	 * <p>
	 * 将key编码为字符串形式的密码
	 * </p>
	 * 
	 * @param key
	 * @return
	 * @throws SecretException
	 * @throws IOException
	 * @throws Exception
	 */
	public static String encodeKey(Key key) throws SecretException {
		try {
			ByteArrayOutputStream strbuf = new ByteArrayOutputStream();
			try {
				ObjectOutputStream objbuf = new ObjectOutputStream(strbuf);
				try {
					objbuf.writeObject(key);
				} finally {
					objbuf.close();
				}
				byte[] bytes = strbuf.toByteArray();
				String str = SecretUtil.encodeBase64(bytes);
				return str;
			} finally {
				strbuf.close();
			}
		} catch (IOException e) {
			throw new SecretException(e);
		}
	}

	/**
	 * 
	 * <p>
	 * 将字符串形式的密码解码为key
	 * </p>
	 * 
	 * @param password
	 * @return
	 * @throws SecretException
	 * @throws Exception
	 */
	public static Key decodeKey(String password) throws SecretException {
		try {
			byte[] bytes = SecretUtil.decodeBase64(password);
			ByteArrayInputStream strbuf = new ByteArrayInputStream(bytes);
			try {
				ObjectInputStream objbuf = new ObjectInputStream(strbuf);
				try {
					Key key = (Key) objbuf.readObject();
					return key;
				} finally {
					objbuf.close();
				}
			} finally {
				strbuf.close();
			}
		} catch (IOException | ClassNotFoundException e) {
			throw new SecretException(e);
		}
	}

	@Override
	public String encrypt(Password password, String plaintext) throws SecretException {
		if (!password.checkValidate()) {
			throw new SecretException("秘钥签名失败");
		}
		return encrypt(password.getPassword(), plaintext);
	}

	@Override
	public String decrypt(Password password, String ciphertext) throws SecretException {
		if (!password.checkValidate()) {
			throw new SecretException("秘钥签名失败");
		}
		return decrypt(password.getPassword(), ciphertext);
	}

}
