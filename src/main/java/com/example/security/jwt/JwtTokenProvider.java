package com.example.security.jwt;

import com.example.util.KeyPairRsa;
import com.example.util.RsaKeyGenerator;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Component
public class JwtTokenProvider {
    @Value("${jwt.token.secret}")
    private String secret;
    @Value("${jwt.token.expiration}")
    private Long validityInMilliseconds;


    private KeyPairRsa keyPairRsa;



    @Autowired
    private UserDetailsService userDetailsService;

    public JwtTokenProvider() throws NoSuchAlgorithmException, IOException {
    }

    public String createToken (String userName, Long id, String sid) throws NoSuchAlgorithmException {
        Claims claims  = Jwts.claims().setSubject(userName);
        claims.put("id", id);
        claims.put("SID", sid);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.RS256, keyPairRsa.getPrivateKey())
                .compact();
    }

    public String getUsername(String token){
        return Jwts.parser().setSigningKey(keyPairRsa.getPublicKey()).parseClaimsJws(token).getBody().getSubject();
    }
    public boolean validateToken(String token) throws InvalidKeySpecException, NoSuchAlgorithmException{
            Jws<Claims> claims = Jwts.parserBuilder().setSigningKey(keyPairRsa.getPublicKey()).build().parseClaimsJws(token);
            if (claims.getBody().getExpiration().before(new Date()))
                return false;
            return true;
    }

    public String resolveToken(HttpServletRequest req){
        String bearerToken = req.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer_")){
            return bearerToken.substring(7, bearerToken.length());
        }
        return null;
    }

    public Authentication getAuthentication(String token){
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(getUsername(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

}
