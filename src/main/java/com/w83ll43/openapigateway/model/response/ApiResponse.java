package com.w83ll43.openapigateway.model.response;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.w83ll43.openapigateway.constant.HttpConstant;
import com.w83ll43.openapigateway.constant.SDKConstant;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.*;

public final class ApiResponse{

    /**
     * 响应状态码
     */
    private int code;

    /**
     * 响应消息
     */
    private String message;

    /**
     * 响应内容类型
     */
    private String contentType;

    /**
     * 响应异常
     */
    private Exception ex;

    /**
     * 响应头
     */
    private Map<String, List<String>> headers = new HashMap<>();

    private byte[] body;

    /**
     * 响应体
     */
    private String bodyStr;

    public ApiResponse(int code){
        this.code = code;
    }

    public ApiResponse(int errorCode, String message, Exception ex){
        this.code = errorCode;
        this.message = message;
        this.ex = ex;
    }

    /**
     * 获取请求头的第一个值
     * @param name
     * @return
     */
    public String getFirstHeaderValue(String name){
        if(headers.containsKey(name) && headers.get(name).size() > 0){
            return headers.get(name).get(0);
        }
        return null;
    }

    /**
     * 添加请求头
     * @param name 键
     * @param value 值
     */
    public void addHeader(String name, String value){
        name = name.trim().toLowerCase();
        addParam(name, value, headers);
    }

    /**
     * 添加请求头
     * @param name
     * @param value
     * @param map
     */
    public void addParam(String name, String value, Map<String, List<String>> map){
        if(map.containsKey(name)){
            map.get(name).add(value);
        } else {
            List<String> values = new ArrayList<>();
            values.add(value == null ? "" : value.trim());
            map.put(name, values);
        }
    }

    public ApiResponse(JsonNode jsonObject) throws IOException, JsonParseException, JsonMappingException {
        this.parse(jsonObject);
        if(jsonObject.get("status") != null) {
            this.code = Integer.parseInt(jsonObject.get("status").asText());
        }
        this.contentType = getFirstHeaderValue(HttpConstant.CLOUDAPI_HTTP_HEADER_CONTENT_TYPE);
        if (null != this.getFirstHeaderValue(SDKConstant.CLOUDAPI_X_CA_ERROR_MESSAGE)) {
            this.message = this.getFirstHeaderValue(SDKConstant.CLOUDAPI_X_CA_ERROR_MESSAGE);
        }
    }

    public void parse(JsonNode message){
        JsonNode headers = message.get("header");
        if(headers != null && headers.size() > 0) {
            Iterator<String> names = headers.fieldNames();
            while (names.hasNext()) {
                String name = names.next();
                if (headers.get(name) != null) {
                    if (headers.get(name).size() > 0) {
                        for (JsonNode value : headers.get(name)) {
                            addHeader(name, value.asText());
                        }
                    } else {
                        addHeader(name, headers.get(name).asText());
                    }
                }
            }
        }

        String contentType = this.getFirstHeaderValue(HttpConstant.CLOUDAPI_HTTP_HEADER_CONTENT_TYPE);
        Charset charset = SDKConstant.CLOUDAPI_ENCODING;
        if(null  != contentType){
            try{
                contentType = contentType.toLowerCase();
                String[] charsetStr = contentType.split(";");
                for(int i = 0 ; i < charsetStr.length ; i++){
                    if(charsetStr[i].contains("charset")){
                        charset = Charset.forName(charsetStr[i].substring(charsetStr[i].indexOf("=") + 1));
                    }
                }
            }catch (Exception ex){
                ex.printStackTrace();
            }
        }

        JsonNode bodyNode = message.get("body");
        if(bodyNode != null){
            bodyStr = bodyNode.asText();
            body = bodyStr.getBytes(charset);
        }
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public Exception getEx() {
        return ex;
    }

    public void setEx(Exception ex) {
        this.ex = ex;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public Map<String, List<String>> getHeaders() {
        return headers;
    }

    public void setHeaders(Map<String, List<String>> headers) {
        this.headers = headers;
    }

    public byte[] getBody() {
        return body;
    }

    public void setBody(byte[] body) {
        this.body = body;
    }

    public String getBodyStr() {
        return bodyStr;
    }

    public void setBodyStr(String bodyStr) {
        this.bodyStr = bodyStr;
    }
}