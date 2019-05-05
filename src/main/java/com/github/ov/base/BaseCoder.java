package com.github.ov.base;

import com.alibaba.fastjson.JSON;
import org.apache.commons.lang3.StringUtils;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

/**
 * @author : JOSE 2019/4/19 7:10 PM
 */
public class BaseCoder {
    // base key
    public static final String KEY_MD5 = "MD5";
    public static final String KEY_RSA = "RSA";

    public static final String ENCODE_CHARSET_UTF_8 = "UTF-8";

    // rsa key
    public static final String KEY_ALGORITHM = "RSA";
    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";
    public static final String PUBLIC_KEY = "RSAPublicKey";
    public static final String PRIVATE_KEY = "RSAPrivateKey";

    public static final String SIGNATURE = "signature";
    public static final String PARAMETER_SEPARATOR = "&";

    public static byte[] decryptBASE64(String key) throws Exception {
        return (new BASE64Decoder()).decodeBuffer(key);
    }

    public static String encryptBASE64(byte[] key) {
        return (new BASE64Encoder()).encodeBuffer(key);
    }

    public static String getJsonContext(Map<String, String> param, String secretKey) {
        TreeMap<String, String> sortParam = new TreeMap<>();
        for (Map.Entry<String, String> entry : param.entrySet()) {
            sortParam.put(entry.getKey(), entry.getValue());
        }

        if (StringUtils.isNotBlank(secretKey)) {
            sortParam.put(BaseCoder.SIGNATURE, secretKey);
        }
        return JSON.toJSONString(sortParam);
    }

    public static String getStringContext(Map<String, String> param, String secretKey) {
        TreeMap<String, String> sortParam = new TreeMap<>();
        for (Map.Entry<String, String> entry : param.entrySet()) {
            sortParam.put(entry.getKey(), entry.getValue());
        }

        StringBuilder sb = new StringBuilder();
        Iterator<String> iterator = sortParam.keySet().iterator();
        while (iterator.hasNext()) {
            String key = iterator.next();
            if (SIGNATURE.equals(key)) {
                continue;
            }

            String value = sortParam.get(key);
            if (StringUtils.isNotBlank(value)) {
                sb.append(key);
                sb.append("=");
                sb.append(value);
                sb.append(PARAMETER_SEPARATOR);
            }
        }

        if (StringUtils.isNotBlank(secretKey)) {
            sb.append(secretKey);
        } else {
            sb.deleteCharAt(sb.length() - 1);
        }
        return sb.toString();
    }

    public static <T> Map<String, String> getParam(T data) throws IllegalAccessException {
        Map<String, String> map = new HashMap<>();

        Field[] fields = data.getClass().getDeclaredFields();
        for (Field field : fields) {
            field.setAccessible(true);
            String value = String.valueOf(field.get(data));
            map.put(field.getName(), value);
        }

        return map;
    }
}
