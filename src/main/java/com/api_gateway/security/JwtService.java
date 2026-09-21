package com.api_gateway.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Service
public class JwtService {

    @Value("${jwt.secret-key}")
    private String secretKey;

    private SecretKey getsecretKey(){
       return Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    public boolean isValidToken(String token){
        try {
            Jwts.parser()
                    .verifyWith(getsecretKey())
                    .build()
                    .parseSignedClaims(token);

            return true;

        }catch (Exception e){
            return false;
        }
    }
}
