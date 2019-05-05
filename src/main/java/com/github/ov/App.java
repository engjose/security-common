package com.github.ov;

import com.github.ov.base.BaseCoder;
import com.github.ov.base.RSACoder;
import com.github.ov.sign.EncryptUtil;
import com.github.ov.sign.SignatureUtil;
import java.util.HashMap;
import java.util.Map;

/**
 * Hello world!
 *
 */
public class App {
    private static String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCv3GtR4POXp2bAKqxnFbc8D4ap1grO3ONlVf4g\n" +
            "61VAw8g7OlXhITrXEC0EW9bDhVfI2WsSf3qihnfkqCKurA0Qvj7ZbcPGQYXu7mpTnAAJnl20Zmik\n" +
            "Gao5Zt2kaSpH4o/GSvaqTigUdi4e1rvptwddj3nPguxAtIWf4wmYPPcmTwIDAQAB";

    private static String privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAK/ca1Hg85enZsAqrGcVtzwPhqnW\n" +
            "Cs7c42VV/iDrVUDDyDs6VeEhOtcQLQRb1sOFV8jZaxJ/eqKGd+SoIq6sDRC+Ptltw8ZBhe7ualOc\n" +
            "AAmeXbRmaKQZqjlm3aRpKkfij8ZK9qpOKBR2Lh7Wu+m3B12Pec+C7EC0hZ/jCZg89yZPAgMBAAEC\n" +
            "gYB6ispRpMG45FJKB7JYpp4nAN6iS97+JJdjzpclkza1yXcmJlEfbgtVPxVPWzt8xNbVwwLEQgZP\n" +
            "aAn1UF/SfVsgLqBPZ93GsLuTCCpcAVdmdQkLjJwzYQB2Vks9rnA1uHKdrhfBJJ0CE4dQrDrmz5x1\n" +
            "cUXoTLVJLk79Jx3ZuwP1wQJBAN3wMO32jOBEBBz8CB7PUDc32PEdKy2xfV8NdMLTTx408EV3NYOR\n" +
            "CatFTuiq/AgNgfHk+1KR65hAucoTFdx03a8CQQDK2eI1vhAc3vFOMmg8u4qv9uIMA4LCQRBwOqyM\n" +
            "exVaV3jJl4VFNdydWVHJA6GataP/DwJ3hsJQS6xz1qhyXAlhAkEAk5vgryQ/5hjWs4Bc1kEEFPWr\n" +
            "8BF6WlWmEMYeVkW8ZVbIRytWCD86sxLRvKWcIq75Mi0dinlKvGSwLNosvAduOQJAEwkbRzvMu0jY\n" +
            "kCP+0CQxQY4DbGkv7ha4+i8nXg9204F93j0PzozdZQ6qtBhZI/GDsD2yV5EXzv0q87vjFsg4QQJA\n" +
            "dUxMbFjDUFrem/c/2HYIppKToY0umnKmRPcz4NxIkSueh4xBjCJiHkLjCODbDUmcFAWnDC4qsQfB\n" +
            "CZVz1a2cZQ==";

    public static void main( String[] args ) throws Exception {
//        Map<String, Object> keyMap = RSACoder.initKey();
//        publicKey = RSACoder.getPublicKey(keyMap);
//        privateKey = RSACoder.getPrivateKey(keyMap);
//        System.err.println("公钥: \n\r" + publicKey);
//        System.err.println("私钥： \n\r" + privateKey);
//
//        testSign();

//        testUriEncode("1saf哈哈你好");
//
//        testMd5("1saf哈哈你好", "123");
//
//        testBase64Encrypt("1saf哈哈你好");

        Map<String, String> map = new HashMap<>();
        map.put("name", "TOM");
        map.put("age", "23");
//        testRsaSign(map);

        testMd5Sign(map);
    }

    public static void testSign() throws Exception {
        System.err.println("私钥加密——公钥解密");
        String inputStr = "sign";
        byte[] data = inputStr.getBytes();
        byte[] encodedData = RSACoder.encryptByPrivateKey(data, privateKey);
        byte[] decodedData = RSACoder.decryptByPublicKey(encodedData, publicKey);

        String outputStr = new String(decodedData);
        System.err.println("加密前: " + inputStr + "\n\r" + "解密后: " + outputStr + "\n\r" + "加密后:" + new String(encodedData));

        System.err.println("私钥签名——公钥验证签名");
        // 产生签名
        String sign = RSACoder.sign(encodedData, privateKey);
        System.err.println("签名:\r" + sign);

        // 验证签名
        boolean status = RSACoder.verify(encodedData, publicKey, sign);
        System.err.println("状态:\r" + status);
    }

    private static void testUriEncode(String source) {
        String encode = EncryptUtil.encode(source);
        System.out.println("encode:" + encode);

        String decode = EncryptUtil.decode(encode);
        System.out.println("decode:" + decode);
    }

    private static void testMd5(String param, String key) {
        String md5 = EncryptUtil.md5Encrypt(param, key);
        System.out.println("md5:" + md5);
    }

    private static void testBase64Encrypt(String param) {
        String base64 = EncryptUtil.base64Encrypt(param);
        System.out.println("base64:" + base64);

        String deBase64 = EncryptUtil.base64Decrypt(base64);
        System.out.println("debase64:" + deBase64);
    }

    private static void testRsa(Map<String, String> param) {
        String rsaData = EncryptUtil.rsaEncrypt(param, privateKey);
        System.out.println("rsaData:" + rsaData);

        String decrypt = EncryptUtil.rsaDecrypt(rsaData, publicKey, String.class);
        System.out.println("decrypt:" + decrypt);
    }

    private static void testRsaSign(Map<String, String> param) {
        String sign = SignatureUtil.sign(param, privateKey, BaseCoder.KEY_RSA);
        System.out.println("sign:" + sign);

        param.put(BaseCoder.SIGNATURE, sign);
        Boolean verifySign = SignatureUtil.verifySign(param, publicKey, BaseCoder.KEY_RSA);
        System.out.println(verifySign);
    }

    private static void testMd5Sign(Map<String, String> param) {
        String sign = SignatureUtil.sign(param, privateKey, BaseCoder.KEY_MD5);
        System.out.println("sign:" + sign);
        param.put(BaseCoder.SIGNATURE, sign);

        Boolean verifySign = SignatureUtil.verifySign(param, privateKey, BaseCoder.KEY_MD5);
        System.out.println(verifySign);
    }
}
