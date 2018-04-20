package com.wangzhong.security;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.InputStream;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.wangzhong.security.CjtRsaPassword;
import com.wangzhong.security.SecretException;


public class RsaFilePasswordTest {

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
	}

	@Before
	public void setUp() throws Exception {
	}

	@Test
	public void testVertify() throws IOException, SecretException {
		String text = "发送报文时，发送方由报文文本计算生成报文摘要";
		InputStream is = RsaFilePasswordTest.class.getClassLoader()
				.getResourceAsStream("pkcs8_rsa_private_sign_key.pem");
		CjtRsaPassword rfp = new CjtRsaPassword(is);
		assertTrue(rfp.checkValidate());
		
		String sign = rfp.getSign(text); 
		assertTrue(rfp.checkSign(text, sign));
	}

}
