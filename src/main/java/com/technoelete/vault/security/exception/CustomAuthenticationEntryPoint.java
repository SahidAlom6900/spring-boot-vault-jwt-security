package com.technoelete.vault.security.exception;
import java.io.IOException;
import java.util.HashMap;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
			throws IOException, ServletException {
		try {
			response.setHeader("error", exception.getMessage());
			response.setStatus(HttpStatus.UNAUTHORIZED.value());
			HashMap<String, String> error = new HashMap<>();
			error.put("statusCode", HttpStatus.UNAUTHORIZED.toString());
			error.put("error", "Full authentication is required to access this resource");
			error.put("message", "Access Denied");
			log.error(exception.getMessage());
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			new ObjectMapper().writeValue(response.getOutputStream(), error);
		} catch (Exception exception2) {
			exception2.printStackTrace();
		}
	}


}
