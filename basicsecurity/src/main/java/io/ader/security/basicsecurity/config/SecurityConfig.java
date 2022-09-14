package io.ader.security.basicsecurity.config;

import io.ader.security.basicsecurity.component.SessionStorageSample;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private SessionStorageSample sessionStorageSample;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated();

        http.formLogin()
                .and()
                    .rememberMe()
                    .rememberMeParameter("remember-me")
                    .tokenValiditySeconds(3600);

        http.sessionManagement()
                .maximumSessions(1) // 최대 허용 가능 세션, -1 : 무제한 로그인 세션 허용
                .maxSessionsPreventsLogin(false) // 동시 로그인 차단, false : 기존 세션 만료(default)
                .expiredUrl("/expired") // 세션이 만료된 경우 이동 할 페이지
                .and().invalidSessionUrl("/invalid"); // 세션이 유효하지 않을 때 이동 할 페이지

        http.formLogin()
                .defaultSuccessUrl("/") // 로그인 성공 후 이동 페이지
                .failureUrl("/login") // 로그인 실패 후 이동 페이지
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("Authentication " + authentication.getName());
                        sessionStorageSample.saveSession("test-token", request.getRequestedSessionId());
                        response.sendRedirect("/");
                    }
                }) // 로그인 성공 후 핸들러
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("Exception " + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                }) // 로그인 실패 후 핸들러
                .permitAll(); // 로그인 페이지 요청 시에는 리소스에 대한 접근 허용

        http.logout() // 로그아웃 처리
                .logoutUrl("/logout") // 로그아웃 처리 Url
                .logoutSuccessUrl("/login") // 로그아웃 성공 후 이동 페이지
                .deleteCookies("JSESSIONID", "remember-me") // 로그아웃 후 쿠키 삭제
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                }) // 로그아웃 핸들러
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                }); // 로그아웃 성공 후 핸들러
    }
}
