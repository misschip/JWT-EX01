package com.cos.jwtex01.config.jwt;

import java.io.IOException;
import java.nio.file.attribute.UserPrincipal;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import com.cos.jwtex01.config.auth.PrincipalDetails;
import com.cos.jwtex01.model.User;
import com.cos.jwtex01.repository.UserRepository;


// 이 클래스는 내가 new 해서 쓸거기 때문에 이 내부에 @Autowired가 안 먹힘
// 인가 <-> 인증(Authentication)
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

	private UserRepository userRepository;
	
	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
		super(authenticationManager);
		this.userRepository = userRepository;

	}
	
	
	@Override	// 오버라이딩된 원래의 doFilterInternal의 작동 부분을 꼭 볼것!
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		String header = request.getHeader(JwtProperties.HEADER_STRING);
		if (header == null || !header.startsWith(JwtProperties.TOKEN_PREFIX)) {
			chain.doFilter(request, response);
		}
		System.out.println("header: " + header);
		
		String token = request.getHeader(JwtProperties.HEADER_STRING)
				.replace(JwtProperties.TOKEN_PREFIX, "");

		
		// 5. 토큰검증(이게 인증이기 때문에 AuthenticationManager가 필요 없음)
		// 내가 SecurityContext에 직접 접근해서 세션을 만들 때 자동으로 UserDeitailsService에 있는 loadByUsername이 호출됨
		String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET))
				.build()
				.verify(token)	// 이 메서드가 핵심
				// .getClaim("username").asString();
				.getSubject();
	
//		DecodedJWT jwt = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(token);
//		System.out.println("JwtAuthorizationFilter: jwt.getClass(): " + jwt.getClass()); //com.auth0.jwt.JWTDecoder
//		System.out.println("JwtAuthorizationFilter: " + jwt.getSubject());
		
		if (username != null) {
			User user = userRepository.findByUsername(username);
			
			// 인증은 토큰 검증시 끝. 인증을 하기 위해서가 아닌 스프링 시큐리티가 수행해주는 권한 처리를 위해 
			// 아래와 같이 토큰을 만들어서 Authentication 객체를 강제로 만들고 그걸 세션에 저장!
			PrincipalDetails principalDetails = new PrincipalDetails(user);
			Authentication authentication = new UsernamePasswordAuthenticationToken(
														principalDetails,	// 나중에 컨트롤러에서 DI해서 쓸 때 사용하기 편함
														null,	// 패스워드는 모르니까 null 처리, 어차피 지금 인증하는게 아니니까!!
														principalDetails.getAuthorities());
			// 강제로 시큐리티의 세션에 접근하여 값 저장
			SecurityContextHolder.getContext().setAuthentication(authentication);
			System.out.println("JwtAuthorizationFilter: SecurityContextHolder.getContext(): " + SecurityContextHolder.getContext());
		}
		
	        // Continue filter execution
	        chain.doFilter(request, response);

	}
	
}

/*
JwtToken에 공백이나 = 등이 들어가면 안됨
JWT에 대해서는 아래 링크 참조
https://velopert.com/2389
*/


/*
클라이언크가 토큰으로 접근시 서버측에서 할일
  - 토큰 검증
  - 유저 ID로 유저 select
  - Authentication 객체 생성
  - 세션 저장

*/