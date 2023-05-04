package com.w83ll43.openapigateway.utils;

import cn.hutool.crypto.digest.MD5;
import com.w83ll43.openapigateway.constant.HttpConstant;
import com.w83ll43.openapigateway.constant.SDKConstant;
import com.w83ll43.openapigateway.exception.SDKException;
import com.w83ll43.openapigateway.model.request.ApiRequest;
import com.w83ll43.openapigateway.model.response.ApiResponse;
import com.w83ll43.openapigateway.signature.ISigner;
import com.w83ll43.openapigateway.signature.ISignerFactory;
import com.w83ll43.openapigateway.signature.SignerFactoryManager;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * 签名工具类
 */
public class SignUtil {

    public static String generateGetSign(String data, String secret) throws UnsupportedEncodingException {
        MD5 md5 = MD5.create();
        byte[] digest = md5.digest(data + secret);
        String sign = new String(digest);
        return URLEncoder.encode(sign, "UTF-8");
    }

    /**
     * 签名方法 将 HttpMethod、Headers、Path、QueryParam、FormParam 合成一个字符串并用 HmacSHA1/HmacSHA256 算法双向加密进行签名
     * @param request
     * @param secret
     * @return
     */
    public static String sign(ApiRequest request, String secret) {
        try {
            String signString = buildStringToSign(request);
            ISignerFactory signerFactory = SignerFactoryManager.findSignerFactory(request.getSignatureMethod());

            if (null == signerFactory) {
                throw new SDKException("不支持的签名方法: " + request.getSignatureMethod());
            }

            // 获取签名工具
            ISigner signer = signerFactory.getSigner();

            if (null == signer) {
                throw new SDKException("Oops!");
            }

            try {
                return signer.sign(signString, secret);
            } catch (Exception e) {
                throw new SDKException(e);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 将 Request 中的 HttpMethod、Headers、Path、QueryParam、FormParam 合成一个字符串
     * @param apiRequest
     * @return
     */
    public static String buildStringToSign(ApiRequest apiRequest) {

        StringBuilder stringBuilder = new StringBuilder();
        // HttpMethod
        stringBuilder.append(apiRequest.getMethod().getValue()).append(SDKConstant.CLOUDAPI_LF);

        // 如果有@"Accept"头 这个头需要参与签名
        if (apiRequest.getFirstHeaderValue(HttpConstant.CLOUDAPI_HTTP_HEADER_ACCEPT) != null) {
            stringBuilder.append(apiRequest.getFirstHeaderValue(HttpConstant.CLOUDAPI_HTTP_HEADER_ACCEPT));
        }
        stringBuilder.append(SDKConstant.CLOUDAPI_LF);

        // 如果有@"Content-MD5"头 这个头需要参与签名
        if (apiRequest.getFirstHeaderValue(HttpConstant.CLOUDAPI_HTTP_HEADER_CONTENT_MD5) != null) {
            stringBuilder.append(apiRequest.getFirstHeaderValue(HttpConstant.CLOUDAPI_HTTP_HEADER_CONTENT_MD5));
        }
        stringBuilder.append(SDKConstant.CLOUDAPI_LF);

        // 如果有@"Content-Type"头 这个头需要参与签名
        if (apiRequest.getFirstHeaderValue(HttpConstant.CLOUDAPI_HTTP_HEADER_CONTENT_TYPE) != null) {
            stringBuilder.append(apiRequest.getFirstHeaderValue(HttpConstant.CLOUDAPI_HTTP_HEADER_CONTENT_TYPE));
        }
        stringBuilder.append(SDKConstant.CLOUDAPI_LF);

        // 签名优先读取 HTTP_CA_HEADER_DATE 因为通过浏览器过来的请求不允许自定义 Date（会被浏览器认为是篡改攻击）
        if (apiRequest.getFirstHeaderValue(HttpConstant.CLOUDAPI_HTTP_HEADER_DATE) != null) {
            stringBuilder.append(apiRequest.getFirstHeaderValue(HttpConstant.CLOUDAPI_HTTP_HEADER_DATE));
        }
        stringBuilder.append(SDKConstant.CLOUDAPI_LF);

        // 将 Headers 合成一个字符串
        stringBuilder.append(buildHeaders(apiRequest));

        // 将 Path、QueryParam、FormParam 合成一个字符串
        stringBuilder.append(buildResource(apiRequest));

        return stringBuilder.toString();
    }

    /**
     * 将 Response 中的 HttpMethod、Headers、Path、QueryParam、FormParam 合成一个字符串
     * @param apiResponse
     * @return
     */
    public static String buildStringToSign(ApiResponse apiResponse){
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(apiResponse.getCode()).append(SDKConstant.CLOUDAPI_LF);
        String signatureHeaders = apiResponse.getFirstHeaderValue(SDKConstant.CLOUDAPI_X_CA_SIGNATURE_HEADERS);

        if(!StringUtils.isBlank(signatureHeaders)){
            signatureHeaders = signatureHeaders.toLowerCase();
            String[] signatureHeaderList = signatureHeaders.split(",");

            for(int i = 0 ; i < signatureHeaderList.length ; i++ ){
                if (apiResponse.getFirstHeaderValue(signatureHeaderList[i]) != null) {
                    stringBuilder.append(apiResponse.getFirstHeaderValue(signatureHeaderList[i]));
                    stringBuilder.append(SDKConstant.CLOUDAPI_LF);
                }
            }
        }

        return stringBuilder.toString();
    }

    /**
     * 将 Path、QueryParam、FormParam 合成一个字符串
     */
    private static String buildResource(ApiRequest request) {
        StringBuilder result = new StringBuilder();
        result.append(request.getPath());

        // 使用 TreeMap 默认按照字母排序
        TreeMap<String , String> parameter = new TreeMap<>();
        if(null!= request.getQuerys() && request.getQuerys().size() > 0){
            for(Map.Entry<String , List<String>> entry : request.getQuerys().entrySet()){
                if(entry.getValue() != null) {
                    parameter.put(entry.getKey(), entry.getValue().get(0));
                }
            }
        }

        if(null != request.getFormParams() && request.getFormParams().size() > 0){
            for(Map.Entry<String , List<String>> entry : request.getFormParams().entrySet()){
                if(entry.getValue() != null) {
                    parameter.put(entry.getKey(), entry.getValue().get(0));
                }
            }
        }

        if(parameter.size() > 0) {
            result.append("?");
            boolean isFirst = true;
            for (String key : parameter.keySet()) {
                if (isFirst == false) {
                    result.append("&");
                } else {
                    isFirst = false;
                }
                result.append(key);
                String value = parameter.get(key);
                if(null != value && !"".equals(value)){
                    result.append("=").append(value);
                }
            }
        }
        return result.toString();
    }

    /**
     *  将 Headers 合成一个字符串
     *  需要注意的是 HTTP 头需要按照字母排序加入签名字符串
     *  同时所有加入签名的头的列表 需要用逗号分隔形成一个字符串 加入一个新HTTP头@"X-Ca-Signature-Headers"
     */
    private static String buildHeaders(ApiRequest apiRequest) {
        // 使用 TreeMap 默认按照字母排序
        Map<String, String> headersToSign = new TreeMap<>();

        StringBuilder signHeadersStringBuilder = new StringBuilder();

        int flag = 0;
        for (Map.Entry<String, List<String>> header : apiRequest.getHeaders().entrySet()) {
            if (header.getKey().startsWith(SDKConstant.CLOUDAPI_CA_HEADER_TO_SIGN_PREFIX_SYSTEM)) {
                if (flag != 0) {
                    signHeadersStringBuilder.append(",");
                }
                flag++;
                signHeadersStringBuilder.append(header.getKey());
                headersToSign.put(header.getKey(), apiRequest.getFirstHeaderValue(header.getKey()));
            }
        }

        // 同时所有加入签名的头的列表 需要用逗号分隔形成一个字符串 加入一个新HTTP头@"X-Ca-Signature-Headers"
        apiRequest.addHeader(SDKConstant.CLOUDAPI_X_CA_SIGNATURE_HEADERS, signHeadersStringBuilder.toString());

        StringBuilder stringBuilder = new StringBuilder();
        for (Map.Entry<String, String> e : headersToSign.entrySet()) {
            stringBuilder.append(e.getKey()).append(':').append(e.getValue()).append(SDKConstant.CLOUDAPI_LF);
        }
        return stringBuilder.toString();
    }

    public static String base64AndMD5(byte[] bytes) {
        if (bytes == null) {
            throw new IllegalArgumentException("参数不能为空");
        }
        try {
            final MessageDigest md = MessageDigest.getInstance("MD5");
            md.reset();
            md.update(bytes);
            byte[] md5Result = md.digest();
            String base64Result = Base64.encodeBase64String(md5Result);
            /*
             * 正常情况下，base64的结果为24位，因与服务器有约定，在超过24位的情况下，截取前24位
             */
            return base64Result.length() > 24 ? base64Result.substring(0, 24) : base64Result;
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("未知算法 MD5");
        }
    }
}
