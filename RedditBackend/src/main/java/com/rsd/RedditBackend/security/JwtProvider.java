package com.rsd.RedditBackend.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;
import com.rsd.RedditBackend.exception.SpringRedditException;

import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.sql.Date;
import java.time.Instant;

import static java.util.Date.from;

@Slf4j
@Service
public class JwtProvider {

    private KeyStore keyStore;

    @Value("${jwt.keystore.location}")
    private String keystoreLocation;

    @Value("${jwt.keystore.alias}")
    private String keyAlias;

    @Value("${jwt.keystore.password}")
    private String keystorePassword;

    @Value("${jwt.expiration.time}")
    private Long jwtExpirationInMillis;

    @PostConstruct
    public void init() {
        try {
            keyStore = KeyStore.getInstance("JKS");
            System.out.println("🔵 Loading KeyStore from: " + keystoreLocation);
            
            InputStream resourceAsStream = getClass().getClassLoader().getResourceAsStream(keystoreLocation);
            if (resourceAsStream == null) {
                throw new SpringRedditException("❌ Keystore file not found at: " + keystoreLocation);
            }

            keyStore.load(resourceAsStream, keystorePassword.toCharArray());
            System.out.println("✅ Keystore loaded successfully.");
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | java.io.IOException e) {
            throw new SpringRedditException("🔥 Exception occurred while loading keystore", e);
        }
    }

    public String generateToken(Authentication authentication) {
        User principal = (User) authentication.getPrincipal();
        System.out.println("🟢 Generating token for user: " + principal.getUsername());

        return Jwts.builder()
                .setSubject(principal.getUsername())
                .setIssuedAt(from(Instant.now()))
                .setExpiration(Date.from(Instant.now().plusMillis(jwtExpirationInMillis)))
                .signWith(getPrivateKey(), SignatureAlgorithm.RS256)
                .compact();
    }

    public String generateTokenWithUserName(String username) {
        log.info("Generating token for user: {}", username);
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(from(Instant.now()))
                .setExpiration(Date.from(Instant.now().plusMillis(jwtExpirationInMillis)))
                .signWith(getPrivateKey(), SignatureAlgorithm.RS256)
                .compact();
    }

    private PrivateKey getPrivateKey() {
        try {
            Key key = keyStore.getKey(keyAlias, keystorePassword.toCharArray());
            System.out.println("key in jwtProvider getPrivatekey: "+key);
            if (key == null) {
                throw new SpringRedditException("❌ Private key not found for alias: " + keyAlias);
            }
            System.out.println("🔑 Private Key Loaded Successfully.");
            return (PrivateKey) key;
        } catch (Exception e) {
            throw new SpringRedditException("🔥 Error retrieving private key from keystore", e);
        }
    }

    public boolean validateToken(String jwt) {
        try {
            System.out.println("🟢 Validating JWT: " + jwt);
            Jwts.parserBuilder()
                .setSigningKey(getPublicKey())
                .build()
                .parseClaimsJws(jwt);
            System.out.println("✅ JWT Token is valid.");
            return true;
        } catch (Exception e) {
            System.out.println("❌ JWT Token validation failed: " + e.getMessage());
            return false;
        }
    }

    private PublicKey getPublicKey() {
        try {
            Certificate cert = keyStore.getCertificate(keyAlias);
            if (cert == null) {
                throw new SpringRedditException("❌ Certificate not found for alias: " + keyAlias);
            }
            return cert.getPublicKey();
        } catch (KeyStoreException e) {
            throw new SpringRedditException("🔥 Error retrieving public key from keystore", e);
        }
    }

    public String getUsernameFromJwt(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getPublicKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }

    public Long getJwtExpirationInMillis() {
        return jwtExpirationInMillis;
    }
}
