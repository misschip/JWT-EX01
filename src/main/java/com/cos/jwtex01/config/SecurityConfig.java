package com.cos.jwtex01.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.cos.jwtex01.config.jwt.JwtAuthenticationFilter;

@Configuration
@EnableWebSecurity	// 시큐리티 활성화 -> 기본 스프링 필터체인에 등록
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();	// 이게 enable 된 상태에서는 POSTMAN 등으로 테스트 불가
		// http.cors().disable();	// javascript 공격이 가능해짐. 위험한 설정
		
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)	// 세션 쓰지 않도록 설정
		
		.and()
		.formLogin().disable()
		.httpBasic().disable()
		.addFilter(new JwtAuthenticationFilter(authenticationManager()))
		//.addFilter(null)
		.authorizeRequests()
		.antMatchers("/api/v1/manager/**")
			.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
		.antMatchers("/api/v1/admin/**")
			.access("hasRole('ROLE_ADMIN')")
		.anyRequest().permitAll();
		// .authenticated();	// 최소 로그인은 해야 나머지 페이지들도 갈 수 있도록
		
			
		
	}
}




/*

* csrf
aop의 post...로 시작하는 메서드 발동으로 작동
login.html 의 input 태그에 csrf token을 달아서 클라이언트로 보내줌
<input type="text" name="username" csrf-token="xxx" />
이 토큰이 없으면 잘못된 접근으로 판단
	-> referer 검증
*/


/*
	인증방식   
			-> 서명방식
	권한방식


*/

/*
 *** JWT ***
header				// HTTP의 body가 아니고 header에 담아서 보냄
	Authorization
		Bearer 토큰		// 토큰은 Base64로 인코딩
		

안드로이드는 토큰을 셰어드 프레퍼런스에 저장

서버는 secret만 들고 있으면 됨. 세션 유지 불요
*/