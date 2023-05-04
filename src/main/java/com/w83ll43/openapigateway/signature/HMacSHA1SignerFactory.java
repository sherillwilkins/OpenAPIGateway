package com.w83ll43.openapigateway.signature;

import com.w83ll43.openapigateway.constant.SDKConstant;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class HMacSHA1SignerFactory implements ISignerFactory{

    /**
     * 签名方法
     */
    public static final String METHOD = "HmacSHA1";

    private static ISigner signer = null;

    /**
     * 创建 HMacSHA1Signer 对象
     * @return
     */
    @Override
    public ISigner getSigner() {

        if (null == signer) {
            signer = new HMacSHA1Signer();
        }

        return signer;
    }

    private static class HMacSHA1Signer implements ISigner {

        /**
         * 签名
         * @param strToSign 待签名字符串
         * @param secretKey 密钥
         * @return 签名后的字符串
         * @throws NoSuchAlgorithmException 无此类算法异常
         * @throws InvalidKeyException 无效密钥异常
         */
        @Override
        public String sign(String strToSign, String secretKey) throws NoSuchAlgorithmException, InvalidKeyException {
            // 1、校验参数不为空
            // 参数 strToSign 不为空
            if (!StringUtils.isNotEmpty(strToSign)) {
                throw new IllegalArgumentException("参数 strToSign 不能为空");
            }

            // 参数 secretKey 不为空
            if (!StringUtils.isNotEmpty(secretKey)) {
                throw new IllegalArgumentException("参数 secretKey 不能为空");
            }

            // 2、签名
            Mac hmacSha1 = Mac.getInstance(METHOD);

            // 使用指定的字符集 UTF-8 将字符串编码为 byte 序列
            byte[] keyBytes = secretKey.getBytes(SDKConstant.CLOUDAPI_ENCODING);
            hmacSha1.init(new SecretKeySpec(keyBytes, 0, keyBytes.length, METHOD));

            // 使用 secretKey 对 strToSign 进行签名
            byte[] md5Result = hmacSha1.doFinal(strToSign.getBytes(SDKConstant.CLOUDAPI_ENCODING));
            return Base64.encodeBase64String(md5Result);
        }

        /**
         * byte 转 String
         * @param data
         * @return
         */
        static String byte2String(byte[] data) {
            StringBuilder stringBuilder = new StringBuilder();

            if (null != data) {
                for (byte b : data) {
                    // String.format("%02x", b) -> 以十六进制输出 2 为指定的输出字段的宽度 如果位数小于 2 则左端补 0
                    stringBuilder.append(String.format("%02x", b));
                }
            }

            return stringBuilder.toString();
        }
    }

}



































