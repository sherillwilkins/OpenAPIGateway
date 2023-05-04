package com.w83ll43.openapigateway.filter;

import com.w83ll43.openapicommon.model.InterfaceInfo;
import com.w83ll43.openapicommon.model.User;
import com.w83ll43.openapicommon.service.InnerInterfaceInfoService;
import com.w83ll43.openapicommon.service.InnerUserService;
import com.w83ll43.openapigateway.constant.SDKConstant;
import com.w83ll43.openapigateway.enums.HttpMethod;
import com.w83ll43.openapigateway.model.request.ApiRequest;
import com.w83ll43.openapigateway.utils.ApiRequestMaker;
import lombok.extern.slf4j.Slf4j;
import org.apache.dubbo.config.annotation.DubboReference;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class CustomGlobalFilter implements GlobalFilter, Ordered {

    private static final Long FIVE_MINUTES = 60 * 5L;

    @DubboReference
    private InnerUserService innerUserService;

    @DubboReference
    private InnerInterfaceInfoService innerInterfaceInfoService;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // 1、用户发送请求到 API 网关

        // 2、请求日志
        ServerHttpRequest request = exchange.getRequest();
        log.info("请求标识 " + request.getId());
        log.info("请求路径 " + request.getPath().value());
        log.info("请求方法 " + request.getMethod());
        log.info("请求参数 " + request.getQueryParams());
        log.info("请求来源 " + request.getRemoteAddress());

        // 3、黑白名单 pass

        // 4、用户鉴权（判断 ak、sk 是否合法）
        HttpHeaders headers = request.getHeaders();
        String appKey = headers.getFirst(SDKConstant.CLOUDAPI_X_CA_KEY);
        String sign = headers.getFirst(SDKConstant.CLOUDAPI_X_CA_SIGNATURE);
        String timestamp = headers.getFirst(SDKConstant.CLOUDAPI_X_CA_TIMESTAMP);
        String nonce = headers.getFirst(SDKConstant.CLOUDAPI_X_CA_NONCE);

        User user = innerUserService.getInvokeUser(appKey);
        // String appSecret = userService.getSecret(appKey);
        String appSecret = user.getSecretKey();

        ServerHttpResponse response = exchange.getResponse();

        // 判断接口是否存在
        String url = "localhost:8081" + request.getPath().value();

        InterfaceInfo interfaceInfo = innerInterfaceInfoService.getInvokeInterface(url);
        if (interfaceInfo == null) {
            log.error("接口不存在！");
            response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
            return response.setComplete();
        }


        String path = request.getPath().value();
        ApiRequest apiRequest = new ApiRequest(HttpMethod.GET, path);

        apiRequest.setHost("localhost:8082");
        apiRequest.addHeader(SDKConstant.CLOUDAPI_X_CA_TIMESTAMP, timestamp);
        apiRequest.addHeader(SDKConstant.CLOUDAPI_X_CA_NONCE, nonce);

        // 为请求添加请求头
        ApiRequestMaker.make(apiRequest , appKey , appSecret);

        String signature = apiRequest.getHeaders().get(SDKConstant.CLOUDAPI_X_CA_SIGNATURE).get(0);

        Long currentTime = System.currentTimeMillis() / 1000;
        if ((currentTime - Long.parseLong(timestamp)) >= FIVE_MINUTES) {
            response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
            return response.setComplete();
        }

        if (!signature.equals(sign)) {
            log.info("签名验证成功!");
            return chain.filter(exchange);
        }

        response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
        return response.setComplete();
    }

    @Override
    public int getOrder() {
        return -100;
    }
}
