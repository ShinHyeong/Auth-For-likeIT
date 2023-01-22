package sg.fp.auth.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import sg.fp.auth.entity.UserEntity;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Slf4j
@Service
public class TokenProvider {
    private static final String SECRET_KEY = "TGlrZUlU";

    /* 유저정보로 jwt 토큰 생성 */
    public String create(UserEntity userEntity){
        //만료기한 : 발급시각으로부터 12시간
        Date expiryDate = Date.from(Instant.now().plus(12, ChronoUnit.HOURS));

        return Jwts.builder()
                .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
                .setSubject(userEntity.uuidToString(userEntity.getId()))
                .setIssuer("LikeIT")
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .compact();
    }

    /* 인증 및 userId 리턴 */
    public String validateAndGetUserId(String token){
        Claims claims = Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token) //base64로 디코딩 및 파싱
                .getBody();

        return claims.getSubject();
    }
}
