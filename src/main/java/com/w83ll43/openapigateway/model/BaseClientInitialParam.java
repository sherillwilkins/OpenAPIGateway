package com.w83ll43.openapigateway.model;

import com.w83ll43.openapigateway.exception.SDKException;

public class BaseClientInitialParam {

    /**
     * appKey
     */
    String appKey;

    /**
     * secretKey
     */
    String appSecret;

    /**
     * 请求地址
     */
    String host;

    /**
     * 连接超时时间
     */
    long connectionTimeout = 10000l;

    /**
     * 读取超时时间
     */
    long readTimeout = 10000l;

    /**
     * 写入超时时间
     */
    long writeTimeout = 10000l;

    public void check(){
        if(isEmpty(appKey) || isEmpty(appKey)){
            throw new SDKException("appKey 和 appSecret 必须初始化");
        }

    }

    protected boolean isEmpty(String str){
        return str == null || str.equals("");
    }

    public String getAppKey() {
        return appKey;
    }

    public void setAppKey(String appKey) {
        this.appKey = appKey;
    }

    public String getAppSecret() {
        return appSecret;
    }

    public void setAppSecret(String appSecret) {
        this.appSecret = appSecret;
    }

    public long getConnectionTimeout() {
        return connectionTimeout;
    }

    public void setConnectionTimeout(long connectionTimeout) {
        this.connectionTimeout = connectionTimeout;
    }

    public long getReadTimeout() {
        return readTimeout;
    }

    public void setReadTimeout(long readTimeout) {
        this.readTimeout = readTimeout;
    }

    public long getWriteTimeout() {
        return writeTimeout;
    }

    public void setWriteTimeout(long writeTimeout) {
        this.writeTimeout = writeTimeout;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }
}
