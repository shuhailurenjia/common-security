对外接口使用说明：
1. 增加接口一对，同时取消原来的CJTRSA加解密传入类型为String的秘钥

```
public static String encrypt(String algorithm, Password password, String plaintext) throws SecretException

public static String decrypt(String algorithm, Password password, String ciphertext) throws SecretException


example:
String text = ...  //明文
String pubKeyPath = ...  //秘钥路径
Password pubPass = new CjtRsaPassword(pubKeyPath);
String encrypted = SecretUtil.encrypt(SecretUtil.CJTRSA, pubPass, text);
...

//解密
String priKeyName = ...
InputStream priSteam = SecretUtilTest.class.getClassLoader().getResourceAsStream(priKeyName);
Password priPass = new CjtRsaPassword(priSteam);
String decrypted = SecretUtil.decrypt(SecretUtil.CJTRSA, priPass, encrypted);

//其它算法的使用接口可以用StringPassword,FilePassword进行封装使用

```


rsaAutoKey.sh 脚本说明：

1. 给定名称自动生成带签名的秘钥对
2. 使用给定的秘钥对文本进行加解密


####脚本参数例子

- 生成秘钥

```
#./rsaAutoKey.sh  gen  test
Generating RSA private key, 1024 bit long modulus
....++++++
....................++++++
e is 65537 (0x10001)
writing RSA key
signed file test_sign_rsa_private_key.pem geneated
signed file test_sign_rsa_public_key.pem geneated
```

- 加密字符串

```
#./rsaAutoKey.sh enc test_sign_rsa_public_key.pem   testEncrps
加密结果为:
gK26seYcZ22TzwrEsL84GtdwjQVXeOm30y9s52s8MDjZFNHIAeyM6JsrCGtyNqQajtw4xU7Js5tPsWqWwMOihiy82wQ7lJp2rMqTOWru9yna/KwpOnHDucCPsifL1RJQ5pr8yyVtlxVq7X3YrbD+S0vRiPFhY8t0qgyfetLy12k=

```


- 解密字符串

```
#./rsaAutoKey.sh dec test_sign_rsa_private_key.pem  gK26seYcZ22TzwrEsL84GtdwjQVXeOm30y9s52s8MDjZFNHIAeyM6JsrCGtyNqQajtw4xU7Js5tPsWqWwMOihiy82wQ7lJp2rMqTOWru9yna/KwpOnHDucCPsifL1RJQ5pr8yyVtlxVq7X3YrbD+S0vRiPFhY8t0qgyfetLy12k=
解密内容:
testEncrps
```
