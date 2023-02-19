package com.technoelete.vault.security.exception;
import java.io.Serializable;
import java.util.Date;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@SuppressWarnings("serial")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ErrorMessage implements Serializable {
	private int statusCode;
	private Date timestamp;
	private String message;
	private String description;
}
