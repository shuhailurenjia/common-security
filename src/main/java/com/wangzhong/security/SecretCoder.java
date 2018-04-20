package com.wangzhong.security;

/**
 * <p>
 * 加密接口
 * </p>
 * 
 * @author zwh
 */
interface SecretCoder {
	/**
	 * 
	 * <p>
	 * 加密 <br/>
	 * </p>
	 * 
	 * @param password
	 *            密码 ,
	 * @param plaintext
	 *            明文
	 * @return 密文
	 */
	String encrypt(String password, String plaintext) throws SecretException;

	String encrypt(Password password, String plaintext) throws SecretException;

	/**
	 * 
	 * <p>
	 * 解密 <br/>
	 * </p>
	 * 
	 * @param password
	 *            密码
	 * @param ciphertext
	 *            密文
	 * @return 明文
	 */
	String decrypt(String password, String ciphertext) throws SecretException;

	String decrypt(Password password, String ciphertext) throws SecretException;
}
