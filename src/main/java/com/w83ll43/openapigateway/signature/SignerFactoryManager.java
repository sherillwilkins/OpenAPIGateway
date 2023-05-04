package com.w83ll43.openapigateway.signature;


import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;
import java.util.Map;


public class SignerFactoryManager {

    private static Map<String, ISignerFactory> factoryMap = new HashMap<>(2);

    /**
     * 添加默认签名工厂
     */
    static {
        registerSignerFactory(HMacSHA256SignerFactory.METHOD, new HMacSHA256SignerFactory());
        registerSignerFactory(HMacSHA1SignerFactory.METHOD, new HMacSHA1SignerFactory());
    }

    /**
     * 注册签名工厂
     * @param method 签名方法 例如 "HmacSHA256" 但不能为空
     * @param factory 工厂 不能为空
     * @return
     */
    public static ISignerFactory registerSignerFactory(String method, ISignerFactory factory) {

        if (StringUtils.isEmpty(method)) {
            throw new IllegalArgumentException("签名方法 method 不能为空");
        }

        if (null == factory) {
            throw new IllegalArgumentException("工厂 factory 不能为空值");
        }

        return factoryMap.put(method, factory);
    }

    /**
     * 根据签名方法找签名工厂
     * @param method 签名方法
     * @return
     */
    public static ISignerFactory findSignerFactory(String method) {

        if (StringUtils.isBlank(method)) {
            method = HMacSHA256SignerFactory.METHOD;
        }

        return factoryMap.get(method);
    }
}