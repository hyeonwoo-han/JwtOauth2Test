package org.zerock.api01.security.filter;

import com.google.gson.Gson;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;
import org.zerock.api01.security.exception.RefreshTokenException;
import org.zerock.api01.util.JWTUtil;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

@Log4j2
@RequiredArgsConstructor
public class RefreshTokenFilter extends OncePerRequestFilter {

    private final String refreshPath;
    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException{

        String path = request.getRequestURI();

        if (!path.equals(refreshPath)) {    // 경로가 /refreshToken 이 아니면 그냥 종료
            log.info("skip refresh token filter..........");
            filterChain.doFilter(request, response);
            return;
        }

        log.info("Refresh Token Filter...... run.............1");
        
        // 전송된 JSON에서 accessToken 과 refreshToken을 얻어온다
        Map<String, String> tokens = parseRequestJSON(request);

        String accessToken = tokens.get("accessToken");
        String refreshToken = tokens.get("refreshToken");

        log.info("accessToken: " + accessToken);
        log.info("refreshToken: " + refreshToken);
        
        // 두 개의 토큰 검증 : 예외 발생 시 메세지 전송, 메소드 종료
        try{
            // 얜 그냥 토큰이 있는지만 검증
            // 기한 만료됐는지 아닌지는 모름
            checkAccessToken(accessToken);
            log.info("Access Token 검증 성공");
        }catch(RefreshTokenException refreshTokenException){
            refreshTokenException.sendResponseError(response);
            return; // 종료
        }

        Map<String, Object> refreshClaims = null;
        try{
            refreshClaims = checkRefreshToken(refreshToken);    // 얜 검증하고 id 추출
            log.info("Refresh Token 검증 성공: " + refreshClaims);
            
            // RefreshToken 유효시간이 조금 남았지만 지나진 않음
            Integer exp = (Integer)refreshClaims.get("exp");    // 만료시간
            Date expTime = new Date(Instant.ofEpochMilli(exp).toEpochMilli() * 1000);
            Date current = new Date(System.currentTimeMillis());    // 현재 시각
            
            // 만료시간과 현재시간의 간격 계산
            // 만약 3일 미만인 경우 RefreshToken도 다시 발행
            long gapTime = (expTime.getTime() - current.getTime());

            log.info("------------------------------------------");
            log.info("current: " + current);
            log.info("expTime: " + expTime);
            log.info("gap: " + gapTime / (1000 * 60 * 60)); // 밀리초를 시간 단위로 보여줌: 30일 = 720시간

            String mid = (String) refreshClaims.get("mid");

            // 여기까지오면 AccessToken은 무조건 새로 생성
            // 1. NO_ACCESS 예외에 걸리지 않았음
            // 2. 기한 만료가 되었건 아니건 AccessToken 자체는 있는 상태
            String accessTokenValue = jwtUtil.generateToken(Map.of("mid", mid), 1);
            String refreshTokenValue = tokens.get("refreshToken");

            // RefreshToken이 3일도 안남았다면 ..
            if(gapTime < (1000 * 60 * 60 * 24 * 3)){
                log.info("new Refresh Token required...");
                refreshTokenValue = jwtUtil.generateToken(Map.of("mid", mid), 30);  // 토큰 재발행
            }

            log.info("Refresh Token Filter result..............");
            log.info("accessToken: " + accessTokenValue);
            log.info("refreshToken: " + refreshTokenValue);

            // 재발행한 토큰들 전송
            log.info("Refresh Token Filter Send Tokens...............");
            sendTokens(accessTokenValue, refreshTokenValue, response);


        }catch(RefreshTokenException refreshTokenException){
            refreshTokenException.sendResponseError(response);
            return; // 종료
        }

    }

    // parse request JSON -> Map<>
    private Map<String, String> parseRequestJSON(HttpServletRequest request) {

        // JSON 데이터를 분석해서 accessToken, refreshToken 전달 값을 Map으로 처리
        try(Reader reader = new InputStreamReader(request.getInputStream())){

            Gson gson = new Gson();

            return gson.fromJson(reader, Map.class);

        }catch(Exception e){
            log.error(e.getMessage());
        }

        return null;
    }

    // accessToken 검증
    public void checkAccessToken(String accessToken) throws RefreshTokenException {
        try{
            // 사실상 검증이라기보다 payload 부분 추출하는 것
            jwtUtil.validateToken(accessToken);
        }catch(ExpiredJwtException expiredJwtException){
            // 만료된 것은 당연하므로 그냥 로그만 찍음
            log.info("AccessToken has expired");
        }catch(Exception exception){
            // 인자로 받아온 accessToken이 null이다
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.NO_ACCESS);
        }
    }
    
    // refreshToken 검증 : refreshToken 존재여부, 잔여 만료일 확인, 토큰생성을 위한 id 확보
    public Map<String, Object> checkRefreshToken(String refreshToken) throws RefreshTokenException{

        try {
            // refreshToken에 담긴 payload 값 추출 및 반환
            Map<String, Object> values = jwtUtil.validateToken(refreshToken);
            return values;
        } catch (ExpiredJwtException expiredJwtException) {
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.OLD_REFRESH);
        } catch (MalformedJwtException malformedJwtException) {
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.NO_REFRESH);
        } catch (Exception exception) {
            new RefreshTokenException(RefreshTokenException.ErrorCase.NO_REFRESH);
        }
        return null;
    }

    // 재발행한 토큰 클라이언트 앱으로 전송
    private void sendTokens(String accessTokenValue, String refreshTokenValue, HttpServletResponse response) {

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Gson gson = new Gson();

        String jsonStr = gson.toJson(Map.of("accessToken", accessTokenValue, "refreshToken", refreshTokenValue));

        try {
            // response 작성 및 전송
            response.getWriter().println(jsonStr);
        } catch (IOException e) {
            throw new RuntimeException();
        }
        
    }

}
