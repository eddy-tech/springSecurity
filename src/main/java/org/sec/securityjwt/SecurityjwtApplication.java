package org.sec.securityjwt;

import org.sec.securityjwt.entities.AppRole;
import org.sec.securityjwt.entities.AppUser;
import org.sec.securityjwt.service.AccountService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled = true)
public class SecurityjwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityjwtApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner start(AccountService accountService){
		return args -> {
            accountService.addNewUser(new AppUser(null,"user1","1234",new ArrayList<>()));
			accountService.addNewUser(new AppUser(null,"user2","1234",new ArrayList<>()));
			accountService.addNewUser(new AppUser(null,"user3","1234",new ArrayList<>()));
			accountService.addNewUser(new AppUser(null,"user4","1234",new ArrayList<>()));

			accountService.addNewRole(new AppRole(null,"ADMIN"));
			accountService.addNewRole(new AppRole(null,"USER"));
			accountService.addNewRole(new AppRole(null,"PRODUCT_MANAGER"));

			accountService.addRoleToUser("user1","USER");
			accountService.addRoleToUser("user1","ADMIN");
			accountService.addRoleToUser("user2","USER");
			accountService.addRoleToUser("user2","PRODUCT_MANAGER");
			accountService.addRoleToUser("user3","USER");
			accountService.addRoleToUser("user4","USER");

		};
	}

}
