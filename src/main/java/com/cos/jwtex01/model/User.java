package com.cos.jwtex01.model;

import javax.persistence.*;

import lombok.Data;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Data
@Entity
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
    private long id;
    private String username;
    private String password;
    private String roles;


    // ENUM으로 안하고 ,(콤마)로 구분해서 ROLE을 입력 -> 이걸 파싱해서 가져옴
    // 데이터베이스 정규화의 원자성을 파괴하는 예외적 경우. 콤마로 여러 값이 들어감
    public List<String> getRoleList(){
        if(this.roles.length() > 0){
            return Arrays.asList(this.roles.split(","));
        }
        return new ArrayList<>();
    }

}
