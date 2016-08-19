package br.com.login.configurations;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		
		auth.inMemoryAuthentication().withUser("root").password("root").roles("ADM");
		auth.inMemoryAuthentication().withUser("user").password("senha").roles("USER");
		
		
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
	
		http.authorizeRequests()
		.antMatchers("/","/login").permitAll()
		.antMatchers("/login/adm/**").access("hasRole('ADM')")
		.antMatchers("/login/user/**").access("hasRole('USER') or hasRole('ADM')")
		.and().formLogin().loginPage("/login").usernameParameter("username").passwordParameter("password");
	}
	
	
}
