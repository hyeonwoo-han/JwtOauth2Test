package org.zerock.api01.util;

import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Map;

@SpringBootTest
@Log4j2
public class JWTUtilTests {

    @Autowired
    private JWTUtil jwtUtil;

    @Test
    public void testGenerate(){

        Map<String, Object> claimMap = Map.of("mid", "ABCDE");  // 불변의 상수 Map을 생성

        String jwtStr = jwtUtil.generateToken(claimMap, 1);

        log.info(jwtStr);
    }

    @Test
    public void testValidate(){
        // 유효시간이 지난 토큰으로 테스트
        // eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2ODMzMDk3NjIsIm1pZCI6IkFCQ0RFIiwiaWF0IjoxNjgzMzA5NzAyfQ.jf0WSvg_Jz4gkBbIuexBVt4kx9Rb0MCvzYoepHPxyuU (정상 문자열)
        String jwtStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2ODMzMDk3NjIsIm1pZCI6IkFCQ0RFIiwiaWF0IjoxNjgzMzA5NzAyfQ.jf0WSvg_Jz4gkBbIuexBVt4kx9Rb0MCvzYoepHPxxieh"; // Signature 부분 임의 수정 -> 예외

        Map<String, Object> claim = jwtUtil.validateToken(jwtStr);

        log.info(claim);
    }

    @Test
    public void testAll(){
        
        // jwt 문자열에 담을 키:값 맵을 작성해서 토큰 생성, 만료일 설정
        String jwtStr = jwtUtil.generateToken(Map.of("mid", "AAAA", "email", "aaaa@bbb.com"), 1);

        log.info(jwtStr);

        Map<String, Object> claim = jwtUtil.validateToken(jwtStr);

        log.info("MID: " + claim.get("mid"));

        log.info("EMAIL: " + claim.get("email"));

    }
}
