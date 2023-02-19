package com.technoelete.vault.security.exception;

import java.io.IOException;
import java.util.HashMap;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class CustomAccessDeniedException implements AccessDeniedHandler {

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			AccessDeniedException exception) throws IOException, ServletException {
		try {
			response.setHeader("error", exception.getMessage());
			response.setStatus(HttpStatus.FORBIDDEN.value());
			HashMap<String, String> error = new HashMap<>();
			error.put("statusCode", HttpStatus.FORBIDDEN.toString());
			error.put("error", "Full authentication is required to access this resource");
			error.put("message", exception.getMessage());
			log.error(exception.getMessage());
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			new ObjectMapper().writeValue(response.getOutputStream(), error);
		} catch (Exception exception2) {
			log.error("Access Denied {}",exception2.getMessage());
		} 
	}


}
