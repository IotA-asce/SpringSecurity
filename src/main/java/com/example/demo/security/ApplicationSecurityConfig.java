package com.example.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
// import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
// import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    public final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http    
                .csrf().disable()   // CROSS SITE REQUEST FORGERY

                // CSRF: ENABLED
                // -------------        Client login    -------------
                // |           | <--------------------- |           |
                // |           | ---------------------> |           |
                // |   SERVER  |        CSRF Token      |   CLIENT  |
                // |           |                        |           |
                // |           | <--------------------- |           |
                // ------------- ---      Client submits-------------
                //          ^      |      form with token: POST | PUT | DELETE
                //          |      |Validates
                //          |______|
                //
                // CSRF protection should be enabled for in browser 
                // ... request processing
                // CSRF protection should be disabled for non-browser 
                // ... request processing

                // .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                // .and()
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll() // whitelisting certain pages from login
                .antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())
                // .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAnyAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
                // .antMatchers(HttpMethod.POST, "/management/api/**").hasAnyAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
                // .antMatchers(HttpMethod.PUT, "/management/api/**").hasAnyAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
                // .antMatchers("/management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(), ApplicationUserRole.ADMINTRAINEE.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
                // .formLogin();
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {

        // return super.userDetailsService();
        UserDetails iotaasce = User.builder()
                .username("iotaasce")
                .password(passwordEncoder.encode("asce@123"))
                // .roles(ApplicationUserRole.STUDENT.name()) // ROLE_STUDENT
                .authorities(ApplicationUserRole.STUDENT.getGrantedAuthorities())
                .build();

        UserDetails adminUserOne = User.builder()
                .username("adminOne")
                .password(passwordEncoder.encode("admin"))
                // .roles(ApplicationUserRole.ADMIN.name())    // ROLE ADMIN
                .authorities(ApplicationUserRole.ADMIN.getGrantedAuthorities())
                .build();

        UserDetails adminUserTwo = User.builder()
                .username("adminTwo")
                .password(passwordEncoder.encode("admin"))
                // .roles(ApplicationUserRole.ADMINTRAINEE.name()) // ROLE ADMINTRAINEE
                .authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(
                iotaasce,
                adminUserOne,
                adminUserTwo
            );

    }
}
