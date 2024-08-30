package com.practice.OAuth2.security;

import com.practice.OAuth2.config.AppProperties;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.stream.Collectors;

@Service
public class TokenProvider {

    private static final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

    private AppProperties appProperties;

    public TokenProvider(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

//    public String createToken(Authentication authentication) {
//        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
//
//        Date now = new Date();
//        Date expiryDate = new Date(now.getTime() + appProperties.getAuth().getTokenExpirationMsec());
//
//        return Jwts.builder()
//                .setSubject(Long.toString(userPrincipal.getId()))
//                .setIssuedAt(new Date())
//                .setExpiration(expiryDate)
//                .signWith(SignatureAlgorithm.HS512, appProperties.getAuth().getTokenSecret())
//                .compact();
//
//    }

    public String createAccessToken(Authentication authentication) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + appProperties.getAuth().getTokenExpirationMsec());

        return Jwts.builder()
                .setSubject(Long.toString(userPrincipal.getId()))
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, appProperties.getAuth().getTokenSecret())
                .compact();
    }

    public String createRefreshToken(Authentication authentication) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + appProperties.getAuth().getRefreshTokenExpirationMsec());

        return Jwts.builder()
                .setSubject(Long.toString(userPrincipal.getId()))
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, appProperties.getAuth().getRefreshTokenSecret())
                .compact();
    }

    // 리프레시 토큰 검증 및 새로운 액세스 토큰 발급
    public String refreshAccessToken(String refreshToken) {
        // 리프레시 토큰 검증
        if (validateRefreshToken(refreshToken)) {
            // 리프레시 토큰에서 사용자 ID 추출
            Claims claims = Jwts.parser()
                    .setSigningKey(appProperties.getAuth().getRefreshTokenSecret())
                    .parseClaimsJws(refreshToken)
                    .getBody();

            String userId = claims.getSubject();

            // 사용자 ID를 사용해 새로운 액세스 토큰 발급
            Date now = new Date();
            Date expiryDate = new Date(now.getTime() + appProperties.getAuth().getTokenExpirationMsec());

            return Jwts.builder()
                    .setSubject(userId)
                    .setIssuedAt(now)
                    .setExpiration(expiryDate)
                    .signWith(SignatureAlgorithm.HS512, appProperties.getAuth().getTokenSecret())
                    .compact();
        } else {
            throw new RuntimeException("Invalid Refresh Token");
        }
    }

    public boolean validateRefreshToken(String refreshToken) {
        try {
            Jwts.parser().setSigningKey(appProperties.getAuth().getRefreshTokenSecret()).parseClaimsJws(refreshToken);
            return true;
        } catch (Exception ex) {
            // 유효하지 않은 리프레시 토큰 처리
        }
        return false;
    }

    public Long getUserIdFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(appProperties.getAuth().getTokenSecret())
                .parseClaimsJws(token)
                .getBody();

        return Long.parseLong(claims.getSubject());
    }

    public boolean validateToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(appProperties.getAuth().getTokenSecret()).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException ex) {
            logger.error("Invalid JWT signature");
        } catch (MalformedJwtException ex) {
            logger.error("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            logger.error("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            logger.error("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            logger.error("JWT claims string is empty.");
        }
        return false;
    }

}
