package com.oauth.resource.configuration;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.Priority;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Priority(SecurityProperties.DEFAULT_FILTER_ORDER - 1)
@Component
public class CSLRequestFilter extends OncePerRequestFilter {


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        HttpServletRequestWrapper wrapper = new HttpServletRequestWrapper(request){
            @Override
            public String getHeader(String name){
                if("ID-Token".equals(name)){
                    return "Test ID-Token";
                }
                return super.getHeader(name);
            }
        };

        filterChain.doFilter(wrapper, response);
    }
}
