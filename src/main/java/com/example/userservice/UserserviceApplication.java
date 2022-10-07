package com.example.userservice;

import com.example.userservice.models.Role;
import com.example.userservice.models.User;
import com.example.userservice.services.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class UserserviceApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserserviceApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(UserService userService) {
		return args -> {
			userService.saveRole(new Role(null, "ROLE_USER"));
			userService.saveRole(new Role(null, "ROLE_MANAGER"));
			userService.saveRole(new Role(null, "ROLE_ADMIN"));
			userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

			userService.saveUser(new User(null, "Johnny body", "john", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "Pikachu", "pika", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "Dikachu", "dika", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "Charizard", "chari", "1234", new ArrayList<>()));

			userService.addRoleToUser("john", "ROLE_USER");
			userService.addRoleToUser("pika", "ROLE_MANAGER");
			userService.addRoleToUser("dika", "ROLE_ADMIN");
			userService.addRoleToUser("chari", "ROLE_SUPER_ADMIN");
		};
	}
}
