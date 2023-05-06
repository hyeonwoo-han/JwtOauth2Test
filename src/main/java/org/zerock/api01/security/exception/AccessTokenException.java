package org.zerock.api01.security.exception;

import com.google.gson.Gson;
import org.springframework.http.MediaType;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.Map;

public class AccessTokenException extends RuntimeException{
    // Access Token에 발생할 수 있는 예외 종류를 enum으로 구분해두고 상황에 맞게 처리

    TOKEN_ERROR token_error;

    public enum TOKEN_ERROR{
        UNACCEPT(401, "Token is null or too short"),
        BADTYPE(401, "Token type Bearer"),
        MALFORM(403, "Malformed Token"),
        BADSIGN(403, "BadSignatured Token"),
        EXPIRED(403, "Expired Token");

        // fields
        private int status;
        private String msg;

        // constructor
        TOKEN_ERROR(int status, String msg){
            this.status = status;
            this.msg = msg;
        }

        // getter
        public int getStatus() {
            return this.status;
        }

        public String getMsg() {
            return this.msg;
        }
    }

    // AccessTokenException constructor
    public AccessTokenException(TOKEN_ERROR error){
        // 인자로 받아온 에러의 이름을 에러메시지로 출력 : RuntimeException -> Exception -> throwable
        super(error.name());
        this.token_error = error;   // http 응답으로 보내기위해 저장
    }

    // 에러를 응답으로 전송
    public void sendResponseError(HttpServletResponse response){

        // 응답의 상태와 content-type 설정
        response.setStatus(token_error.getStatus());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        
        // 응답 Map -> json으로 변환
        Gson gson = new Gson();
        String responseStr = gson.toJson(Map.of("msg", token_error.getMsg(), "time", new Date()));  // 에러메시지, 해당 시간
        
        try{
            // HTTP 응답 PrintWriter 객체 생성 및 본문 작성
            response.getWriter().println(responseStr);
        }catch(IOException e){
            throw new RuntimeException(e);
        }
    }
}
