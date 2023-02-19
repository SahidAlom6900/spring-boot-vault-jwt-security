package com.technoelete.vault.security.auth;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.technoelete.vault.security.config.JwtService;
import com.technoelete.vault.security.exception.CustomAccessDeniedException;
import com.technoelete.vault.security.user.Role;
import com.technoelete.vault.security.user.User;
import com.technoelete.vault.security.user.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {
	private final CustomAccessDeniedException accessDenied;
	private final UserRepository repository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final AuthenticationManager authenticationManager;

	public AuthenticationResponse register(RegisterRequest request) {
		var user = User.builder().firstname(request.getFirstname()).lastname(request.getLastname())
				.email(request.getEmail()).password(passwordEncoder.encode(request.getPassword())).role(Role.USER)
				.build();
		repository.save(user);
		return AuthenticationResponse.builder().build();
	}

	public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest, HttpServletRequest request,
			HttpServletResponse response) {
		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getEmail(),
					authenticationRequest.getPassword()));
		} catch (Exception exception) {
			try {
				log.error(exception.getMessage());
				accessDenied.handle(request, response, new AccessDeniedException(exception.getMessage()));
			} catch (Exception exception2) {
				log.error(exception2.getMessage());
			}
		}
		User user = repository.findByEmail(authenticationRequest.getEmail()).orElseThrow();
		var jwtToken = jwtService.generateToken(user);
		return AuthenticationResponse.builder().accessToken(jwtToken[0]).refreshToken(jwtToken[1]).build();
	}

	public AuthenticationResponse refreshToken(AuthenticationRequest authenticationRequest, HttpServletRequest request,
			HttpServletResponse response) {
		jwtService.validateJwtToken(authenticationRequest.getToken());
		User user = repository.findByEmail(jwtService.extractUsername(authenticationRequest.getToken())).orElseThrow();
		var jwtToken = jwtService.generateAccessToken(user, authenticationRequest.getToken());
		return AuthenticationResponse.builder().accessToken(jwtToken[0]).refreshToken(jwtToken[1]).build();
	}
}
