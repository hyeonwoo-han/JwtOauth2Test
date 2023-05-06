package org.zerock.api01.security.handler;

import com.google.gson.Gson;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.zerock.api01.util.JWTUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

@Log4j2
@RequiredArgsConstructor
public class APILoginSuccessHandler implements AuthenticationSuccessHandler {

    // JWTUtil 주입
    private final JWTUtil jwtUtil;

    // 인증 성공 시 실행
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException{

        log.info("Login Success Handler -----------------------");

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);  // reseponse json

        log.info(authentication);
        log.info("username: " + authentication.getName());

        Map<String, Object> claim = Map.of("mid", authentication.getName());    // key: mid, value: authentication.getName()
        
        // AccessToken 유효기간 1일
        String accessToken = jwtUtil.generateToken(claim, 1);
        // RefreshToken 유효기간 30일
        String refreshToken = jwtUtil.generateToken(claim, 30);

        Gson gson = new Gson();

        Map<String, String> keyMap = Map.of("accessToken", accessToken, "refreshToken", refreshToken);

        String jsonStr = gson.toJson(keyMap);   // 토큰들을 담은 맵

        response.getWriter().println(jsonStr);  // getWriter(): http 응답 본문 작성을 위한 PrintWriter 객체 반환, println(): 본문 작성
    }
}
