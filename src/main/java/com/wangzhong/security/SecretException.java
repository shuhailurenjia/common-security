package com.wangzhong.security;

/**
 * <p>
 * 加解密异常
 * </p>
 * 
 * @author zwh
 */
public class SecretException extends Exception {
	private static final long serialVersionUID = 1L;

	public SecretException(String message) {
		super(message);
	}

	public SecretException(Throwable cause) {
		super(cause);
	}

	public SecretException(String message, Throwable cause) {
		super(message, cause);
	}
}
