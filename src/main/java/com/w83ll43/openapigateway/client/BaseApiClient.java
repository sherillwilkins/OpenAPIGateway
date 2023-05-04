package com.w83ll43.openapigateway.client;

import com.w83ll43.openapigateway.exception.SDKException;
import com.w83ll43.openapigateway.model.request.ApiRequest;
import com.w83ll43.openapigateway.model.response.ApiResponse;

/**
 * apiClient基类
 *
 * @author VK.Gao
 * @date 2017/03/02
 */
public abstract class BaseApiClient {

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
     * 是否已经初始化
     */
    boolean isInit = false;

    protected void checkIsInit(){
        if(!isInit){
            throw new SDKException("使用前必须初始化客户端");
        }
    }

    /**
     * 发送同步请求
     * @param apiRequest
     * @return
     */
    protected abstract ApiResponse sendSyncRequest(ApiRequest apiRequest);

//    /**
//     * 发送异步请求
//     * @param apiRequest
//     * @param apiCallback
//     */
//    protected abstract void sendAsyncRequest(final ApiRequest apiRequest , final ApiCallback apiCallback);
}
