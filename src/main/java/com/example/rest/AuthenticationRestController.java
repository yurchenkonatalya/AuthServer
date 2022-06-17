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

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.NoSuchAlgorithmException;
import java.util.*;

@RestController
@RequestMapping(value = "/api/users/auth/")
public class AuthenticationRestController {
    private AuthenticationManager authenticationManager;
    private JwtTokenProvider jwtTokenProvider;
    private UserService userService;

    @Autowired
    public AuthenticationRestController(AuthenticationManager authenticationManager, JwtTokenProvider jwtTokenProvider, UserService userService) throws NoSuchAlgorithmException, IOException {
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.userService = userService;
//        RsaKeyGenerator rs = new RsaKeyGenerator();
    }

    @PostMapping("login")
    public ResponseEntity login(@RequestBody AuthenticationRequestDto requestDto) {
        try {
            String username = requestDto.getUsername();
//            User user  = userService.findByUsername(username);
//            if(user == null){
//                throw new UsernameNotFoundException("User with user nsme: " + username + " not found ");
//            }
            Hashtable<String, String> environment = new Hashtable<String, String>();
            environment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            environment.put(Context.PROVIDER_URL, "ldap://192.168.100.3:389");
            environment.put(Context.SECURITY_AUTHENTICATION, "simple");
            environment.put(Context.SECURITY_PRINCIPAL, username);
            environment.put(Context.SECURITY_CREDENTIALS, requestDto.getPassword());
//            environment.put("com.sun.jndi.ldap.connect.pool", "true");
            environment.put("java.naming.ldap.attributes.binary", "objectSID");

            DirContext context = new InitialDirContext(environment);
//            LdapContext ctx = new InitialLdapContext(environment);
            Attributes attributes = getUserAttributes(username, context);
            byte[] bytes = (byte[]) attributes.get("objectSID").get();
            String strSID = convertSidToStr(bytes);
            Long id = userService.findByObjectSID(strSID).getId();

            context.close();
            String token = jwtTokenProvider.createToken(username, 1L, strSID);

            Map<Object, Object> response = new HashMap<>();
            response.put("username", username);
            response.put("token", token);
            return ResponseEntity.ok(response);
        } catch (AuthenticationException e) {
            throw new BadCredentialsException("Invalid username or password");
        } catch (NamingException e) {
            Map<Object, Object> response = new HashMap<>();
            response.put("username", requestDto.getUsername());
            response.put("error", "incorrect login or password");
            return ResponseEntity.badRequest().body(response);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    @PostMapping("isTokenValid")
    public ResponseEntity isTokenValid(@RequestBody JwtDto requestDto) {
        try {
            String token = requestDto.getToken();
            String username = requestDto.getUsername();
            Boolean isTokenValid = jwtTokenProvider.validateToken(token);
            Map<Object, Object> response = new HashMap<>();
            response.put("username", username);
            response.put("token", token);
            response.put("isValid", isTokenValid.toString());
            return ResponseEntity.ok(response);
        }catch (Exception e){
            return ResponseEntity.ok("ddd");
        }
    }

    private Attributes getUserAttributes(String username, DirContext ctx) {
        try {
            String[] splitStr = username.split("[@]");
            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            /* String[] attrIDs = { "mail", "telephonenumber" };
             You can have multiple attributes like SN, telephonenumber, mail
            etc.. */
            String[] attrIDs = {"mail", "displayName", "objectSID", "distinguishedName"};
            constraints.setReturningAttributes(attrIDs);
            NamingEnumeration<SearchResult> answer = ctx.search("OU=test-ou,DC=cit,DC=local", "(sAMAccountName=" + splitStr[0] + ")", constraints);
            if (answer.hasMore()) {
                Attributes attrs = (answer.next()).getAttributes();
                System.out.println(attrs.get("mail").get());
                System.out.println(attrs.get("displayName").get());
                byte[] bytes = (byte[]) attrs.get("objectSID").get();
                System.out.println(bytes.length);
                System.out.println(convertSidToStr(bytes));
                System.out.println(attrs.get("distinguishedName").get());

                return attrs;
            } else {
                throw new Exception("Invalid User");
            }

        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public static String convertSidToStr(byte[] sid) {
        if (sid == null) return null;
        if (sid.length < 8 || sid.length % 4 != 0) return "";
        StringBuilder sb = new StringBuilder();
        sb.append("S-").append(sid[0]);
        int c = sid[1]; // Init with Subauthority Count.
        ByteBuffer bb = ByteBuffer.wrap(sid);
        // bb.order(ByteOrder.BIG_ENDIAN); // Not needed, default big endian.
        sb.append("-").append((long) bb.getLong() & 0XFFFFFFFFFFFFL);
        bb.order(ByteOrder.LITTLE_ENDIAN); // Now switch.
        for (int i = 0; i < c; i++) { // Create Subauthorities.
            sb.append("-").append((long) bb.getInt() & 0xFFFFFFFFL);
        }
        return sb.toString();
    }
}


