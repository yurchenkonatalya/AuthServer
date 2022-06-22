package com.example.service.impl;

import com.example.dto.AuthenticationRequestDto;
import com.example.dto.JwtDto;
import com.example.model.User;
import com.example.repository.UserRepository;
import com.example.security.jwt.JwtTokenProvider;
import com.example.service.LdapService;
import com.example.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

@Service
@Slf4j
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final LdapService ldapService;
    private final JwtTokenProvider jwtTokenProvider;

    @Autowired
    public UserServiceImpl(UserRepository userRepository, LdapService ldapService, JwtTokenProvider jwtTokenProvider) {
        this.userRepository = userRepository;
        this.ldapService = ldapService;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    public ResponseEntity login(AuthenticationRequestDto authRequest) {
        try {
            DirContext context = ldapService.generateDirContext(authRequest.getUsername(), authRequest.getPassword());
            String[] attr = {"objectSID"};
            Attributes attributes = ldapService.getUserAttributes(authRequest.getUsername(), attr, context);
            byte[] bytes = (byte[]) attributes.get("objectSID").get();
            String strSID = ldapService.convertSidToStr(bytes);
            User user = userRepository.findByObjectSID(strSID);
            context.close();
            String token = null;
            if (user != null) {
                token = jwtTokenProvider.createToken(authRequest.getUsername(), user.getId(), user.getObjectSID());
            }
            Map<Object, Object> response = new HashMap<>();
            response.put("username", authRequest.getUsername());
            response.put("token", token);
            return ResponseEntity.ok(response);
        } catch (NamingException e) {
            throw new BadCredentialsException("Invalid username or password");
        } catch (NoSuchAlgorithmException e) {
            throw new BadCredentialsException("Invalid algorithm");
        }
    }

    @Override
    public ResponseEntity isTokenValid(JwtDto isTokenValidRequest) throws InvalidKeySpecException, NoSuchAlgorithmException {
        String token = isTokenValidRequest.getToken();
        String username = isTokenValidRequest.getUsername();
        boolean isTokenValid = jwtTokenProvider.validateToken(token);
        Map<Object, Object> response = new HashMap<>();
        response.put("username", username);
        response.put("token", token);
        response.put("isValid", Boolean.toString(isTokenValid));
        return ResponseEntity.ok(response);
    }
}
