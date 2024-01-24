package com.simbolmina.auth.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${spring.application.jwt.access-secret}")
    private String ACCESS_SECRET_KEY;

    @Value("${spring.application.jwt.refresh-secret}")
    private String REFRESH_SECRET_KEY;

    public String extractEmail(String token, boolean isAccessToken) {
        return extractClaim(token, Claims::getSubject, isAccessToken);
    }


    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver, boolean isAccessToken) {
        final Claims claims = extractAllClaims(token, isAccessToken);
        return claimsResolver.apply(claims);
    }


    public String generateAccessToken(UserDetails userDetails){
        return generateAccessToken(new HashMap<>(), userDetails);
    }

    public String generateRefreshToken(UserDetails userDetails){
        return generateRefreshToken(new HashMap<>(), userDetails);
    }

    public String generateAccessToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getAccessSignInKey(), SignatureAlgorithm.HS256)
                .compact();

    }

    public String generateRefreshToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24 * 30))
                .signWith(getRefreshSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }


    public boolean isAccessTokenValid(String token, UserDetails userDetails) {
        final String email = extractEmail(token, true); // true for access token
        return email.equals(userDetails.getUsername()) && isTokenNotExpired(token, true);
    }

    public boolean isRefreshTokenValid(String token, UserDetails userDetails) {
        final String email = extractEmail(token, false); // false for refresh token
        return email.equals(userDetails.getUsername()) && isTokenNotExpired(token, false);
    }


    private boolean isTokenNotExpired(String token, boolean isAccessToken) {
        return extractExpiration(token, isAccessToken).after(new Date());
    }

    private Date extractExpiration(String token, boolean isAccessToken) {
        return extractClaim(token, Claims::getExpiration, isAccessToken);
    }

    public Claims extractAllClaims(String token, boolean isAccessToken) {
        Key signingKey = isAccessToken ? getAccessSignInKey() : getRefreshSignInKey();
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }


    private Key getAccessSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(ACCESS_SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private Key getRefreshSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(REFRESH_SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
