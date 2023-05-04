package com.w83ll43.openapigateway.client;

import com.w83ll43.openapigateway.constant.HttpConstant;
import com.w83ll43.openapigateway.exception.SDKException;
import com.w83ll43.openapigateway.model.request.ApiRequest;
import com.w83ll43.openapigateway.model.response.ApiResponse;
import com.w83ll43.openapigateway.utils.ApiRequestMaker;
import com.w83ll43.openapigateway.utils.HttpCommonUtil;
import com.w83ll43.openapigateway.utils.SignUtil;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.EntityBuilder;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;

public class ApacheHttpClient extends BaseApiClient {

    private CloseableHttpClient httpClient;

    protected ApacheHttpClient(){}

    public void init(String appKey, String appSecret, String host) {

        // 创建请求配置信息
        RequestConfig defaultConfig = RequestConfig.custom()
                // 创建请求配置信息
                .setConnectTimeout(10000)
                // 设置响应超时时间
                .setSocketTimeout(10000)
                // 设置从连接池获取链接的超时时间
                .setConnectionRequestTimeout(10000)
                .build();

        httpClient = HttpClients.custom()
                // 设置默认参数
                .setDefaultRequestConfig(defaultConfig)
                .build();

        this.appKey = appKey;
        this.appSecret = appSecret;
        this.host = host;
    }


    private HttpUriRequest buildRequest(ApiRequest apiRequest) {

        apiRequest.setHost(this.host);

        // 为请求添加请求头
        ApiRequestMaker.make(apiRequest , appKey , appSecret);

        RequestBuilder builder = RequestBuilder.create(apiRequest.getMethod().getValue());

        /*
         *  拼接URL
         *  HTTP + HOST + PATH(With PathParameter) + Query Parameter
         */
        try {
            URIBuilder uriBuilder = new URIBuilder();
            uriBuilder.setScheme("http");
            uriBuilder.setHost(apiRequest.getHost());
            uriBuilder.setPath(apiRequest.getPath());
            if (!HttpCommonUtil.isEmpty(apiRequest.getQuerys())) {
                for (Entry<String, List<String>> entry : apiRequest.getQuerys().entrySet()) {
                    for(String value : entry.getValue()){
                        uriBuilder.addParameter(entry.getKey(), value);
                    }

                }
            }
            builder.setUri(uriBuilder.build());
        } catch (URISyntaxException e) {
            throw new SDKException("构建 HTTP 请求 URI 失败", e);
        }

        EntityBuilder bodyBuilder = EntityBuilder.create();

        // 设置请求数据类型
        if(null == apiRequest.getFirstHeaderValue(HttpConstant.CLOUDAPI_HTTP_HEADER_CONTENT_TYPE)) {
            bodyBuilder.setContentType(ContentType.parse(apiRequest.getMethod().getRequestContentType()));
        }
        else{
            bodyBuilder.setContentType(ContentType.parse(apiRequest.getFirstHeaderValue(HttpConstant.CLOUDAPI_HTTP_HEADER_CONTENT_TYPE)));
        }

        if (!HttpCommonUtil.isEmpty(apiRequest.getFormParams())) {
            /*
             *  如果 formParams 不为空
             *  将 Form 中的内容以 urlQueryParams 的格式存放在body中 (k1=v1&k2=v2&k3=v3)
             */
            List<NameValuePair> paramList = new ArrayList<>();

            for (Entry<String, List<String>> entry : apiRequest.getFormParams().entrySet()) {
                for(String value : entry.getValue()) {
                    paramList.add(new BasicNameValuePair(entry.getKey(), value));
                }
            }
            bodyBuilder.setParameters(paramList);
            builder.setEntity(bodyBuilder.build());
        } else if (!HttpCommonUtil.isEmpty(apiRequest.getBody())) {
            bodyBuilder.setBinary(apiRequest.getBody());
            builder.setEntity(bodyBuilder.build());
        }

        for (Entry<String, List<String>> entry : apiRequest.getHeaders().entrySet()) {
            for(String value : entry.getValue()){
                builder.addHeader(entry.getKey(), value);
            }
        }

        return builder.build();
    }

    private ApiResponse parseToApiResponse(HttpResponse httpResponse) throws IOException {
        ApiResponse result = new ApiResponse(httpResponse.getStatusLine().getStatusCode());

        // headers
        result.setHeaders(new HashMap<>());
        for (Header header : httpResponse.getAllHeaders()) {
            List<String> values = result.getHeaders().get(header.getName());

            if(values == null){
                values = new ArrayList<>();
            }

            values.add(header.getValue());
            result.getHeaders().put(header.getName().toLowerCase() , values);
        }

        // message
        result.setMessage(httpResponse.getStatusLine().getReasonPhrase());

        if(httpResponse.getEntity() != null){
            // content type
            Header contentType = httpResponse.getEntity().getContentType();
            if(contentType != null){
                result.setContentType(contentType.getValue());
            }
            else
            {
                result.setContentType(HttpConstant.CLOUDAPI_CONTENT_TYPE_TEXT);
            }

            // body
            result.setBody(EntityUtils.toByteArray(httpResponse.getEntity()));

            String contentMD5 = result.getFirstHeaderValue(HttpConstant.CLOUDAPI_HTTP_HEADER_CA_CONTENT_MD5);
            if(null != contentMD5 && !"".equals(contentMD5)){
                String localContentMd5 = SignUtil.base64AndMD5(result.getBody());
                if(!contentMD5.equalsIgnoreCase(localContentMd5)){
                    throw new SDKException("Server Content MD5 does not match body content , server md5 is " + contentMD5 + "  local md5 is " + localContentMd5 + " body is " + new String(result.getBody()));
                }
            }
        }else{
            String contentTypeStr = result.getFirstHeaderValue(HttpConstant.CLOUDAPI_HTTP_HEADER_CONTENT_TYPE);
            if(null == contentTypeStr){
                contentTypeStr = HttpConstant.CLOUDAPI_CONTENT_TYPE_TEXT;
            }
            result.setContentType(contentTypeStr);
        }
        return result;
    }

    @Override
    public final ApiResponse sendSyncRequest(ApiRequest apiRequest) {
        HttpUriRequest httpRequest = buildRequest(apiRequest);
        CloseableHttpResponse httpResponse = null;
        try {
            httpResponse = httpClient.execute(httpRequest);
            return parseToApiResponse(httpResponse);
        } catch (IOException e) {
            throw new SDKException(e);
        } finally {
            HttpCommonUtil.closeQuietly(httpResponse);
        }
    }

    public void shutdown() {
        HttpCommonUtil.closeQuietly(httpClient);
    }

}
