package org.zerock.api01.util;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.sql.Date;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.Map;

@Component
@Log4j2
public class JWTUtil {

    @Value("${org.zerock.jwt.secret}")  // application.properties 설정파일에서 지정한 값이 클래스 필드에 자동으로 할당된다
    private String key;                 // hello1234567890

    // JWT 문자열 생성
    public String generateToken(Map<String, Object> valueMap, int days){

        log.info("generateKey..." + key);

        // 헤더 부분
        Map<String, Object> headers = new HashMap<>();
        headers.put("typ", "JWT");  // 타입: JWT
        headers.put("alg","HS256"); // 해싱 알고리즘 종류

        // payload 부분 설정
        Map<String, Object> payloads = new HashMap<>();
        payloads.putAll(valueMap);

        // 테스트는 편의를 위해 분단위로 설정 -> 나중에 60*24 일단위 변경
        int time = (60 * 24) * days;  // 다시 하루로 설정

        // JWT 문자열 생성
        String jwtStr = Jwts.builder()
                .setHeader(headers) // 헤더설정
                .setClaims(payloads)    // 페이로드 설정
                .setIssuedAt(Date.from(ZonedDateTime.now().toInstant()))    // 생성일자
                .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(time).toInstant()))    // 만료일자
                .signWith(SignatureAlgorithm.HS256, key.getBytes()) // Signature 설정
                .compact();

        // JWT 문자열 반환
        return jwtStr;
    }

    // JWT 문자열 검증: JWT 안에 담긴 내용 확인
    public Map<String, Object> validateToken(String token) throws JwtException {

        Map<String, Object> claim = null;

        // parser()로 실세로 검증 처리: key를 넣고 복호화 후 payload 의 body 부분 반환
        claim = Jwts.parser()
                .setSigningKey(key.getBytes())  // set key
                .parseClaimsJws(token)  // 파싱 및 검증, 실패 시 에러
                .getBody();

        return claim;
    }
}
