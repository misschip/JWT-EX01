package com.cos.jwtex01.config.jwt;

public interface JwtProperties {
	String SECRET = "조익현";	// 우리 서버만 알고 있는 비밀값
	int EXPIRATION_TIME = 864000000;	// 10일
	String TOKEN_PREFIX = "Bearer ";	// 뒤에 빈칸 한칸 반드시!
	String HEADER_STRING = "Authorization";	// 이것 변수명은 그냥 AUTHORIZATION이 적당할 듯!
}
