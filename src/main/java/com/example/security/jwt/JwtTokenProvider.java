package com.example.security.jwt;

import com.example.util.KeyPairRsa;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;

@Component
@Slf4j
public class JwtTokenProvider {
    @Value("${jwt.token.expiration}")
    private Long validityInMilliseconds;

    private final KeyPairRsa keyPairRsa = new KeyPairRsa();

    private final UserDetailsService userDetailsService;

    public JwtTokenProvider(UserDetailsService userDetailsService) throws Exception {
        this.userDetailsService = userDetailsService;
    }

    public String createToken(String userName, Long id, String sid) {
        Claims claims = Jwts.claims().setSubject(userName);
        claims.put("id", id);
        claims.put("SID", sid);

//        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
//        generator.initialize(2048, new SecureRandom());
//        KeyPair pair = generator.generateKeyPair();

        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(keyPairRsa.getPrivateKey(), SignatureAlgorithm.RS256)
                .compact();
    }

    public String getUsername(String token) {
        return Jwts.parserBuilder().setSigningKey(keyPairRsa.getPublicKey()).build().parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateToken(String token) {
        log.warn("qqqqqqq");
        try {
            Jws<Claims> claims = Jwts.parserBuilder()
                    .setSigningKey(keyPairRsa.getPublicKey())
                    .build()
                    .parseClaimsJws(token);
            log.warn(claims.toString());
            return !claims.getBody().getExpiration().before(new Date());
        }catch (Exception e){
            return false;
        }
    }

    public String resolveToken(HttpServletRequest req) {
        String bearerToken = req.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer_")) {
            return bearerToken.substring(7, bearerToken.length());
        }
        return null;
    }

    public Authentication getAuthentication(String token) {
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(getUsername(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }
}
