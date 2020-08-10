package com.cos.jwtex01;



import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter;

@SpringBootTest
public class BasicAuthenticationConverterTest {

	@org.junit.jupiter.api.Test
	public void conterverTest() {
		System.out.println(MyAuthenticationConverter.AUTHENTICATION_SCHEME_BASIC);
	}
}


class MyAuthenticationConverter extends BasicAuthenticationConverter {
	public static final String AUTHENTICATION_SCHEME_BASIC = "Bearer";
	

}