package com.example.rest;

import com.example.dto.AuthenticationRequestDto;
import com.example.dto.JwtDto;
import com.example.dto.ValidDto;
import com.example.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.naming.NamingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@RestController
@RequestMapping(value = "/api/users/auth/")
@Slf4j
@CrossOrigin(origins = "http://localhost:63342")
public class AuthenticationRestController {
    private final UserService userService;

    @Autowired
    public AuthenticationRestController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("login")
    public ResponseEntity<JwtDto> login(@RequestBody AuthenticationRequestDto requestDto) throws NamingException, NoSuchAlgorithmException {
        log.error(requestDto.getUsername());
        return userService.login(requestDto);
//        return ResponseEntity.ok(new JwtDto("oklknkml", "200nklm"));
    }

    @PostMapping("isTokenValid")
    public ResponseEntity isTokenValid(@RequestBody JwtDto requestDto) throws InvalidKeySpecException, NoSuchAlgorithmException {
        log.error(requestDto.getUsername());
        return userService.isTokenValid(requestDto);
    }

    @GetMapping("checkToken")
    public ResponseEntity checkToken(@RequestParam String token) {
        log.error(userService.checkToken(token).getBody().toString());
        return userService.checkToken(token);
    }
}


