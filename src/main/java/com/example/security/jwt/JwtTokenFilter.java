package com.example.security.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class JwtTokenFilter extends GenericFilter {
    private final JwtTokenProvider tokenProvider;

    @Autowired
    public JwtTokenFilter(JwtTokenProvider tokenProvider){
        this.tokenProvider = tokenProvider;
    }
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        String token = tokenProvider.resolveToken((HttpServletRequest) servletRequest);
        try {
            if(token != null && tokenProvider.validateToken(token)){
                Authentication authentication = tokenProvider .getAuthentication(token);
                if(authentication != null){
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        filterChain.doFilter(servletRequest, servletResponse);
    }
}