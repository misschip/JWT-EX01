package com.cos.jwtex01.config.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.cos.jwtex01.model.User;
import com.cos.jwtex01.repository.UserRepository;

@Service
public class PrincipalDetailsService implements UserDetailsService{

	@Autowired
	private UserRepository userRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		System.out.println("PrincipalDetailsService: 진입");
		User user = userRepository.findByUsername(username);	// 유저를 못 찾은 경우는 UsernameNotFoundException 던져짐
		
		// session.setAttribute("loginUser", user);	// 이렇게 세션에 저장해도 된다고 쌤이(비공식)
		return new PrincipalDetails(user);
	}

}
