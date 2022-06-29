package com.example.service;

import com.example.dto.AuthenticationRequestDto;
import com.example.dto.JwtDto;
import com.example.dto.ValidDto;
import org.springframework.http.ResponseEntity;

import javax.naming.NamingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public interface UserService {
    ResponseEntity login(AuthenticationRequestDto authRequest) throws NamingException, NoSuchAlgorithmException;
    ResponseEntity isTokenValid(JwtDto isTokenValidRequest) throws InvalidKeySpecException, NoSuchAlgorithmException;
    ResponseEntity checkToken(String token);
}
