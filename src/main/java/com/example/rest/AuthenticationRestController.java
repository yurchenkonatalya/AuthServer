package com.example.rest;

import com.example.dto.AuthenticationRequestDto;
import com.example.dto.JwtDto;
import com.example.security.jwt.JwtTokenProvider;
import com.example.service.UserService;
import com.example.util.RsaKeyGenerator;
import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.WinNT;
import org.apache.catalina.util.ToStringUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.naming.NamingException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@RestController
@RequestMapping(value = "/api/users/auth/")
public class AuthenticationRestController {
    private final UserService userService;

    @Autowired
    public AuthenticationRestController(UserService userService) {
        this.userService = userService;

    }

    @PostMapping("login")
    public ResponseEntity login(@RequestBody AuthenticationRequestDto requestDto) throws NamingException, NoSuchAlgorithmException {
        return userService.login(requestDto);
    }

    @PostMapping("isTokenValid")
    public ResponseEntity isTokenValid(@RequestBody JwtDto requestDto) throws InvalidKeySpecException, NoSuchAlgorithmException {
        return userService.isTokenValid(requestDto);
    }
}


