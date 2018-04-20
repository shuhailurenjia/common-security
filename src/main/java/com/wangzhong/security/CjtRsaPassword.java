package com.wangzhong.security;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RSA 文件秘钥<br/>
 * 签名算法为 SHA256withRSA<br/>
 * 生成签名秘钥过程如下：<br/>
 * <code> 秘钥生成 <br/> 或者参考资源文件中 generateKeys.sh 
 *  openssl genrsa -out rsa_private_key.pem 1024  <br/>
 *  openssl rsa -in rsa_private_key.pem -out rsa_public_key.pem -pubout <br/>
 *  openssl pkcs8 -topk8 -in rsa_private_key.pem -out pkcs8_rsa_private_key.pem -nocrypt <br/>
 *  签名秘钥：<br/>
 *  openssl dgst  -sha256 -sign 另外一组私钥.pem  -keyform PEM   pkcs8_rsa_private_key.pem    | base64  > pkcs8_rsa_private_sign_key.pem; cat pkcs8_rsa_private_key.pem >> pkcs8_rsa_private_sign_key.pem<br/>
 *  openssl dgst  -sha256 -sign 另外一组私钥.pem  -keyform PEM   rsa_public_key.pem    | base64  >rsa_public_sign_key.pem; cat rsa_public_key.pem >> rsa_public_sign_key.pem
 * </code>
 * @author zwh
 */
public class CjtRsaPassword extends FilePassword {

	public static enum RsaKeyEnum{
		PUBKEY,
		PRIKEY
	}
	
	/**
	 * 秘钥包含签名内容,需要进行签名认证
	 */
	private final String signRsaPubKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9kLp9DWCjLkvgmLpxbeFT6v0Y"+
									"sa1LP3G8CoSwRusa/CPvl6jNlQ/3GkMUmxvLgwJHcXQ0F/tD4y4RpF0LRe2bdy55"+
									"E4Xmk7PNakJtsxQgjHD7oLFF6WLaA6LCetbd3lMJZ0locwJKjeJa34jx+dNYKhjR"+
									"3EvW4dcvP8kx99K27wIDAQAB";
	
	private final String signRsaPriKey = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAL2Qun0NYKMuS+CY" +
									"unFt4VPq/RixrUs/cbwKhLBG6xr8I++XqM2VD/caQxSbG8uDAkdxdDQX+0PjLhGk"+
									"XQtF7Zt3LnkTheaTs81qQm2zFCCMcPugsUXpYtoDosJ61t3eUwlnSWhzAkqN4lrf"+
									"iPH501gqGNHcS9bh1y8/yTH30rbvAgMBAAECgYB8ICWMttK9ZxY2JauHlHyD943s"+
									"uoMPj6aIi5ag2n8d91YMj5DvtJh0pBSijIIhu1Ilt8twRPe5VyuWT7rBI/PVxQZY"+
									"WadOmWDcqG8vMIstPTx+ybYwkIjvSibVrvMY2jEMkgHG2Ov+Q8WpSmuTNfB2uslx"+
									"IY2YLVU7HZcGTSYWgQJBAOPi2PKC7Bf754a0ohEGMwAVkKJ2gruGitKzzf6Xu9pg"+
									"FgfseDx2frLvDmNU6VKZhKLriQDoSmvzqReSxvDIrsECQQDU86AUy9TRkOIOpmfW"+
									"OhwyS/Fxj9Lbt8PvxVii7DHk3npxwLaR1oUQOq6o7YdxL5LOYwFDrKb4zO4Hy333"+
									"lIGvAkBqD9x1EmYby4w4b722OrJl6aOFWa8C5F2cLz9CrRArVOksCuzzBxt04DpM"+
									"FOr7HKRUx1beaz6n+6HJbPDWhDCBAkASVgPjpoVlog8E6eko9gn1frqEZ7jlOFaD"+
									"r79pD+Nf7JQodUqDFjCQ7Cyb2Q//e/QtFzNFq3kZFTQtsaTgC4Z7AkBNVPxkv0UR"+
									"Squ1H5CsDQVMeNxVWIXDrFX/kJWzVxTr52lcvvXpWyvnRfQgqLR1UZtnpMkubikW"+
									"pjtCAlrcq7zy";
	
	
	private Password signRsaPubPass = new RsaPassword(signRsaPubKey);
	private Password signRsaPriPass = new RsaPassword(signRsaPriKey);
	
	/**
	 * 签名算法
	 */
	private static final String SIGN_ALGORITHMS = "SHA256withRSA";
	
	public CjtRsaPassword(String pathName) throws IOException, SecretException {
		super(pathName);
		loadSignAndKey();
	}
	
	public CjtRsaPassword(InputStream inStream) throws IOException, SecretException {
		super(inStream);
		loadSignAndKey();
	}
	
	/**
	 * 设置验证签名的公钥
	 * @param signRsaPubKey
	 */
	public void setSignRsaPubKey(String signRsaPubKey) {
		this.signRsaPubPass = new RsaPassword(signRsaPubKey);
	}
	
	/**
	 * 设置获取签名的私钥
	 * @param signRsaPriKey
	 */
	public void setSignRsaPriKey(String signRsaPriKey) {
		this.signRsaPriPass = new RsaPassword(signRsaPriKey);
	}

	private void loadSignAndKey() throws SecretException{
		int findex = fileContent.indexOf("\n");
		if(findex > 0 && fileContent.charAt(findex+1) =='-'){
			signature = fileContent.substring(0, findex);
			keyValue = fileContent.substring(findex+1, fileContent.length());
			keyType = checkKeyType(keyValue);
		}else{
			throw new SecretException("key file lack of signature!");
		}
	}
	
	private RsaKeyEnum checkKeyType(String fullKey){
		if(fullKey.indexOf("PRIVATE")>0){
			return RsaKeyEnum.PRIKEY;
		}
		return RsaKeyEnum.PUBKEY;
	}

	/**
	 * 秘钥签名
	 */
	private String signature;
	/**
	 * 秘钥
	 */
	private String keyValue;
	
	/**
	 * 秘钥类型,private OR public key
	 */
	
	private RsaKeyEnum keyType;
	
	public RsaKeyEnum getKeyType() {
		return keyType;
	}

	@Override
	public String getPassword() {
		int begin = keyValue.indexOf("-\n");
		int end = keyValue.lastIndexOf("\n-");
		if (begin > 0 && end > 0) {
			return keyValue.substring(begin + 2, end);
		}
		return keyValue;
	}

	@Override
	public boolean checkValidate() {
		return checkSign(keyValue,signature);
	}
	
	/**
	 * 获取签名,使用默认的秘钥,签名算法为SHA256withRSA
	 * @param text
	 * @return
	 * @throws SecretException 
	 */
	public String getSign(String text) throws SecretException {
		Signature signature;
		try {
			signature = Signature.getInstance(SIGN_ALGORITHMS);
			byte[] keyBytes = SecretUtil.decodeBase64(signRsaPriPass.getPassword());
			PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance(CjtRsaCoder.KEY_ALGORITHM);
			PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);

			signature.initSign(privateK);
			signature.update(text.getBytes());
			return SecretUtil.encodeBase64(signature.sign());
		} catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException | SignatureException e) {
			throw new SecretException(e);
		}

	}
	
	/**
	 * 签名认证. <br/>
	 * 算法为:SHA256withRSA
	 * @param text
	 * @param sign
	 * @return
	 * @throws SecretException 
	 */
	public boolean checkSign(String text,String sign) {
		try {
			byte[] keyBytes = SecretUtil.decodeBase64(signRsaPubPass.getPassword());
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance(CjtRsaCoder.KEY_ALGORITHM);
			PublicKey publicK = keyFactory.generatePublic(x509KeySpec);

			Signature signature = Signature.getInstance(SIGN_ALGORITHMS);

			signature.initVerify(publicK);
			signature.update(text.getBytes("UTF-8"));

			boolean bverify = signature.verify(SecretUtil.decodeBase64(sign));
			return bverify;

		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

}
