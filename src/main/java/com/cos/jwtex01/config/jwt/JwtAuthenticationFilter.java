package com.cos.jwtex01.config.jwt;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwtex01.config.auth.PrincipalDetails;
import com.cos.jwtex01.dto.LoginRequestDto;
import com.cos.jwtex01.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {


	private final AuthenticationManager authenticationManager;

	
	
	// Authentication 객체 만들어서 리턴 => 의존: AuthenticationManager
	// 인증 요청시에 실행되는 함수 => /login (attempAuthentication 말고 filter()를 오버라이딩해서 구현하는 경우도 있음)
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		
		// request에 있는 username과 password를 파싱해서 가져오기
		ObjectMapper om = new ObjectMapper();
		LoginRequestDto loginRequestDto = null;
		try {
			loginRequestDto = om.readValue(request.getInputStream(), LoginRequestDto.class);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		// 유저네임, 패스워드로 토큰 만들기
		UsernamePasswordAuthenticationToken authenticationToken =
				new UsernamePasswordAuthenticationToken(
						loginRequestDto.getUsername(),
						loginRequestDto.getPassword());
		
		// authenticate()함수가 호출되면 AuthenticationProvider가 UserDetailsService의
		// loadUserByUsername(토큰의 첫번째 파라미터)를 호출하고
		// UserDetails를 리턴 받아서 토큰의 두번째 파라미터(credentials)와
		// UserDetails(DB값)의 getPassword() 함수를 비교해서 동일하면
		// Authentication 객체를 만들어서 필터체인을 리턴해 준다.
		
		// <팁> AuthenticationProvider의 디폴트 서비스는 UserDetailsService 타입이고
		//	AuthenticationProvider의 디폴트 암호화 방식은 BCryptPasswordEncoder임
		// 이 두가지를 사용할 때는 AuthenticationProvider에게 알려줄 필요가 없음
		

		
		// Authentication 객체 만들기(Authentication 객체는 UserDetailsService를 통해서 만들어진다)
		Authentication authentication = 
				authenticationManager.authenticate(authenticationToken);
				// BCryptPasswordEncoder와 UserDetailsService는 기본값이어서 굳이 안 알려줘도 된다고
		
		PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
		System.out.println("Authentication: " + principalDetails.getUser().getUsername());
		return authentication;
	}

	// JWT Token 생성해서 응답해 주기(response에 담아서 다음 필터 체인으로 넘어감). 토큰은 header에 담음
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		
		PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
		
		// Base64로 인코딩. 이 결과물을 Header에 key Authorization, value는 Bearer ... 로 된 긴 문자열로 보내게 되는데 value에 해당하는 부분이 바로 아래에서 얻은 결과물임
		String jwtToken = JWT.create()
				.withSubject(principalDetails.getUsername()) 	// .withClaim("sub","이름")과 동일
				.withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))	// 8640000 == 10일
				.withClaim("id",principalDetails.getUser().getId())	// 등록되지 않은 클레임 등록 방식임
				.withClaim("username",principalDetails.getUser().getUsername())
				.sign(Algorithm.HMAC512(JwtProperties.SECRET));	// "조익현" 문자열 값은 secret 값이므로 회사에서는 1주일에 한 번 정도 바꿔줘야 하고. 실제로는 좀 더 긴 문자열을 사용!
													// 이게 털리면 끝!
		
		response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);	// Authorization : Bearer ....
		
		/* 쿠키에 담을 경우
		response.addHeader("set-cookies", JwtProperties.TOKEN_PREFIX + jwtToken);
		Cookie cookie = new Cookie("Authorization", jwtToken);
		response.addCookie(cookie);
		*/
		
		// super.successfulAuthentication(request, response, chain, authResult);
		
	}

}

/*
 JwtToken
 
 - 쿠키에 담아서 보낼 수 (setCookies, httpOnly)
 - jsp나 react는 로컬 스토리지에 담을 수(10일짜리로 해놓으면 웹브라우저 껐다 다음날에도 바로 됨), 안드로이드는 셰어드 프레퍼런스에 저장 (jsp는 세션 스토리지에도 담을 수 있는 듯. 웹브라우저 껐다 켜면 다시 로그인 해야)
   	요청시에 꺼내서 헤더에 담아 요청
 
 */


/*


UsernamePasswordAuthenticationFilter -> AuthenticationManager -> 

Username...filter가 원래는 세션(SecuritySession)에 저장함.
근데 우리는 세션은 이용하지 않을 것임
오버라이딩해서 토큰 만들도록 구현한 게 위 소스

*/