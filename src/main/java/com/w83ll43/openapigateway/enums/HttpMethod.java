package com.w83ll43.openapigateway.enums;

import com.w83ll43.openapigateway.constant.HttpConstant;

/**
 * HTTP 请求方法
 */
public enum HttpMethod {

    /**
     * HTTP GET 请求
     * 表单提交 接受 JSON
     */
    GET("GET", HttpConstant.CLOUDAPI_CONTENT_TYPE_FORM, HttpConstant.CLOUDAPI_CONTENT_TYPE_JSON),

    /**
     * HTTP POST 请求
     * 表单提交 接受 JSON
     */
    POST_FORM("POST", HttpConstant.CLOUDAPI_CONTENT_TYPE_FORM, HttpConstant.CLOUDAPI_CONTENT_TYPE_JSON),

    /**
     * HTTP POST 请求
     * stream 流提交 (文件上传) 接受 JSON
     */
    POST_BODY("POST", HttpConstant.CLOUDAPI_CONTENT_TYPE_STREAM, HttpConstant.CLOUDAPI_CONTENT_TYPE_JSON),

    /**
     * HTTP PUT 请求
     * 表单提交 接受 JSON
     */
    PUT_FORM("PUT", HttpConstant.CLOUDAPI_CONTENT_TYPE_FORM, HttpConstant.CLOUDAPI_CONTENT_TYPE_JSON),

    /**
     * HTTP PUT 请求
     * stream 流提交 (文件上传) 接受 JSON
     */
    PUT_BODY("PUT", HttpConstant.CLOUDAPI_CONTENT_TYPE_STREAM, HttpConstant.CLOUDAPI_CONTENT_TYPE_JSON),

    /**
     * HTTP PATCH 请求
     * 表单提交 接受 JSON
     */
    PATCH_FORM("PATCH", HttpConstant.CLOUDAPI_CONTENT_TYPE_FORM, HttpConstant.CLOUDAPI_CONTENT_TYPE_JSON),

    /**
     * HTTP PUT 请求
     * stream 流提交 (文件上传) 接受 JSON
     */
    PATCH_BODY("PATCH", HttpConstant.CLOUDAPI_CONTENT_TYPE_STREAM, HttpConstant.CLOUDAPI_CONTENT_TYPE_JSON),

    /**
     * HTTP DELETE 请求
     * 表单提交 接受 JSON
     */
    DELETE("DELETE", HttpConstant.CLOUDAPI_CONTENT_TYPE_FORM, HttpConstant.CLOUDAPI_CONTENT_TYPE_JSON),

    /**
     * HTTP HEAD 请求
     * 表单提交 接受 JSON
     */
    HEAD("HEAD", HttpConstant.CLOUDAPI_CONTENT_TYPE_FORM, HttpConstant.CLOUDAPI_CONTENT_TYPE_JSON),

    /**
     * HTTP OPTIONS 请求
     * 表单提交 接受 JSON
     */
    OPTIONS("OPTIONS", HttpConstant.CLOUDAPI_CONTENT_TYPE_FORM, HttpConstant.CLOUDAPI_CONTENT_TYPE_JSON);

    private String value;

    /**
     * 请求内容类型
     */
    private String requestContentType;

    /**
     * 接受内容类型
     */
    private String acceptContentType;

    HttpMethod(String value, String requestContentType, String acceptContentType) {
        this.value = value;
        this.requestContentType = requestContentType;
        this.acceptContentType = acceptContentType;
    }

    public String getValue() {
        return value;
    }

    public String getRequestContentType() {
        return requestContentType;
    }

    public String getAcceptContentType() {
        return acceptContentType;
    }
}
