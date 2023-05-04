package com.w83ll43.openapigateway.constant;

/**
 * HTTP 协议相关常量
 */
public class HttpConstant {

    // 请求 Header Accept
    public static final String CLOUDAPI_HTTP_HEADER_ACCEPT = "accept";
    // 请求 Body 内容 MD5 Header
    public static final String CLOUDAPI_HTTP_HEADER_CONTENT_MD5 = "content-md5";
    // 请求 Body 内容 MD5 Header
    public static final String CLOUDAPI_HTTP_HEADER_CA_CONTENT_MD5 = "x-ca-content-md5";
    // 请求 Header Content-Type
    public static final String CLOUDAPI_HTTP_HEADER_CONTENT_TYPE = "content-type";
    // 请求 Header UserAgent
    public static final String CLOUDAPI_HTTP_HEADER_USER_AGENT = "user-agent";
    // 请求 Header Date
    public static final String CLOUDAPI_HTTP_HEADER_DATE = "date";
    // 请求 Header Host
    public static final String CLOUDAPI_HTTP_HEADER_HOST = "host";

    // 表单类型 Content-Type
    public static final String CLOUDAPI_CONTENT_TYPE_FORM = "application/x-www-form-urlencoded; charset=utf-8";
    // 流类型 Content-Type
    public static final String CLOUDAPI_CONTENT_TYPE_STREAM = "application/octet-stream; charset=utf-8";
    // JSON 类型 Content-Type
    public static final String CLOUDAPI_CONTENT_TYPE_JSON = "application/json; charset=utf-8";
    // XML 类型 Content-Type
    public static final String CLOUDAPI_CONTENT_TYPE_XML = "application/xml; charset=utf-8";
    // 文本类型 Content-Type
    public static final String CLOUDAPI_CONTENT_TYPE_TEXT = "application/text; charset=utf-8";
}
