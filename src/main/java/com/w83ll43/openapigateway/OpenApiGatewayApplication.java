package com.w83ll43.openapigateway;

import org.apache.dubbo.config.spring.context.annotation.EnableDubbo;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;

@EnableDubbo
@SpringBootApplication(exclude= {DataSourceAutoConfiguration.class})
@ComponentScan("com.w83ll43.openapigateway.filter")
public class OpenApiGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(OpenApiGatewayApplication.class, args);
    }

}
