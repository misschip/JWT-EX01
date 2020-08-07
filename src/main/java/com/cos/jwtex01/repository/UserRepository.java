package com.cos.jwtex01.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.cos.jwtex01.model.User;

public interface UserRepository extends JpaRepository<User, Long>{	// Long은 User의 id 타입과 일치
	User findByUsername(String username);
}
