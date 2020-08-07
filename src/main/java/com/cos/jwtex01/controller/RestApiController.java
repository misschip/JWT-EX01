package com.cos.jwtex01.controller;

import java.util.List;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.cos.jwtex01.model.User;
import com.cos.jwtex01.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor	// @Autowired와 비슷한 기능. 요즘은 @RequiredArgsConstructor를 많이 쓴다고
@RequestMapping("api/v1")
// @CrossOrigin	// CORS 허용. 컨트롤러 자체에 걸기보다 특정 메서드에만 거는 게 바람직함. http.cors().disable()과 동일 작용
public class RestApiController {
	
	private final UserRepository userRepository;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;

	// 모든 사람이 접근 가능
	@GetMapping("home")
	public String home() {
		return "<h1>home</h1>";
	}
	
	// 매니저가 접근 가능(admin 포함)
	@GetMapping("manager/reports")
	public String reports() {
		return "<h1>reports</h1>";
	}
	
	// admin이 접근 가능
	@GetMapping("admin/user")
	public List<User> users() {
		return null;
	}
	
	
	@PostMapping("join")
	public String join(@RequestBody User user) {
		user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
		user.setRoles("ROLE_USER");
		userRepository.save(user);
		
		return "회원가입완료";
	}
}	
	/*
	 POSTMAN으로 http://localhost:8080/api/v1/join 주소로 POST 방식으로
	 body -> raw -> JSON 선택 후
	 { "username" : "ssar", "password" : 1234 } 를 보내면 바로 회원가입완료 메세지가 뜬다.
	 
	 */
	
	/*
	 @PostMapping("login") 단 메서드는 따로 안 만들어도
	 
	 */
	 

