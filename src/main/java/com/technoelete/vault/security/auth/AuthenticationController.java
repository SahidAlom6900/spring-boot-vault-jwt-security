package com.technoelete.vault.security.auth;

import lombok.RequiredArgsConstructor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

	private final AuthenticationService service;

	@PostMapping("/register")
	public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request) {
		return ResponseEntity.ok(service.register(request));
	}

	@PostMapping("/authenticate")
	public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest authenticationRequest,
			HttpServletRequest request, HttpServletResponse response) {
		return ResponseEntity.ok(service.authenticate(authenticationRequest, request, response));
	}
	
	@PostMapping("/refresh-token")
	public ResponseEntity<AuthenticationResponse> generateRefreshToken(@RequestBody AuthenticationRequest authenticationRequest,
			HttpServletRequest request, HttpServletResponse response) {
		return ResponseEntity.ok(service.refreshToken(authenticationRequest, request, response));
	}

}
