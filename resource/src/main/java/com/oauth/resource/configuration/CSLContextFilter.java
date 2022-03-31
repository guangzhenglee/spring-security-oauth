package com.oauth.resource.configuration;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.Priority;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

@Priority(SecurityProperties.DEFAULT_FILTER_ORDER + 1)
@Component
public class CSLContextFilter extends OncePerRequestFilter {


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {


        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        Map<String, Object> claims = jwt.getClaims();

        String iatHeader = request.getHeader("authority");

        System.out.println("-------------------------");
        System.out.println(claims);
        System.out.println("-------------------------");
        System.out.println(iatHeader);
        System.out.println("-------------------------");

        System.out.println(request.getHeader("ID-Token"));
        System.out.println("-------------------------");

        // add new header "id_token" = iatHeader

        filterChain.doFilter(request, response);
    }
}
