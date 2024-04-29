package com.coskun.jwttoken.service;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET = "ctwGj5hEs2vWKGlq1Mh636lzcx0YQWXJ/arB/P5EFp2nzl/G+W0wnA17n1tQ9Ub6";

    public String generateToken(UserDetails user) {

        return Jwts.builder()
                .subject(user.getUsername())
                .claim("authorities", populateAuthorities(user.getAuthorities()))
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 86400000))
                .signWith(getSigninKey())
                .compact();
    }

    private String populateAuthorities(Collection<? extends GrantedAuthority> authorities) {

        Set<String> authoritiesSet = new HashSet<>();
        for (GrantedAuthority authority : authorities) {
            authoritiesSet.add(authority.getAuthority());
        }
        return String.join(",",authoritiesSet);

    }

    private SecretKey getSigninKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigninKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String extractUsername(String token) {

        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
}
