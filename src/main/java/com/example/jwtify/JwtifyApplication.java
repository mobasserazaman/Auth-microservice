package com.example.jwtify;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.example.jwtify.user.Role;
import com.example.jwtify.user.User;
import com.example.jwtify.user.UserRepository;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@SpringBootApplication
public class JwtifyApplication {

	private final UserRepository userRepository;
	private final BCryptPasswordEncoder passwordEncoder;

	public static void main(String[] args) {
		SpringApplication.run(JwtifyApplication.class, args);
	}

	@Bean
	CommandLineRunner createAdmin(){
		return args -> {
			if(!userRepository.existsByEmail("admin@example.com")){
				User admin = User.builder().email("admin@example.com").password(passwordEncoder.encode("Admin")).role(Role.ADMIN).build();
				userRepository.save(admin);
			}
		};
	}

}
