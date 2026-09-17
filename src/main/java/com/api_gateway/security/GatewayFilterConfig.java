package com.api_gateway.security;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayFilterConfig {

    @Bean
    public GlobalFilter jwtAuthenticationFilter(JwtService jwtService){
        return new JwtAuthenticationFilter(jwtService);
    }

}
