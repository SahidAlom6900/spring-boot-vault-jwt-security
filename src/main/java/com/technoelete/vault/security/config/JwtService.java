package com.technoelete.vault.security.config;

import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.technoelete.vault.security.user.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class JwtService {
//cQfTjWnZr4u7w!z%C*F-JaNdRgUkXp2s5v8y/A?D(G+KbPeShVmYq3t6w9z$C&E) vault

	@Value("${auth.app.jwt-secret}")
	private String secretKey = "qwerty";

	@Value("${auth.app.jwt-expiration-ms}") // 24*60*60*1000
	private int jwtExpirationMs;

	@Value("${auth.app.jwt-refresh-ms}") // 15*24*60*60*1000
	private int jwtRefreshMs;

	@Value("${auth.app.jwt-not-before-ms}") // 3*1000
	private int jwtNotBefore;

	private Map<String, String> jwtTocketIds = new HashMap<>();

	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}

	public String[] generateToken(User user) {
		return generateToken(new HashMap<>(), user);
	}

	public String[] generateAccessToken(User user, String refreshToken) {
		String uuid = extractClaim(refreshToken, Claims::getId);
		String accessToken = Jwts.builder()
				.claim("roles",
						user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
				.setIssuer("FLINKO TEAM").setSubject(user.getUsername())
				.setAudience(user.getFirstname() + " " + user.getLastname())
				.setExpiration(new Date(Date.from(Instant.now()).getTime() + jwtExpirationMs))
				.setNotBefore(new Date(Date.from(Instant.now()).getTime() + jwtNotBefore))
				.setIssuedAt(Date.from(Instant.now())).setHeaderParam("typ", "JWT").setId(uuid)
				.signWith(getSignInKey(), SignatureAlgorithm.HS512).compact();
		return new String[] { accessToken, refreshToken };
	}

	public String[] generateToken(Map<String, Object> extraClaims, User user) {
		String uuid = UUID.randomUUID().toString();
		this.jwtTocketIds.put(user.getUsername(), uuid);
		String accessToken = Jwts.builder()
				.claim("roles",
						user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
				.setIssuer("FLINKO TEAM").setSubject(user.getUsername())
				.setAudience(user.getFirstname() + " " + user.getLastname())
				.setExpiration(new Date(Date.from(Instant.now()).getTime() + jwtExpirationMs))
				.setNotBefore(new Date(Date.from(Instant.now()).getTime() + jwtNotBefore))
				.setIssuedAt(Date.from(Instant.now())).setHeaderParam("typ", "JWT").setId(uuid)
				.signWith(getSignInKey(), SignatureAlgorithm.HS512).compact();

		String refreshToken = Jwts.builder().setIssuer("FLINKO TEAM").setSubject(user.getUsername())
				.setAudience(user.getFirstname() + " " + user.getLastname())
				.setExpiration(new Date(Date.from(Instant.now()).getTime() + jwtExpirationMs))
				.setNotBefore(new Date(Date.from(Instant.now()).getTime() + jwtNotBefore))
				.setIssuedAt(Date.from(Instant.now())).setHeaderParam("typ", "JWT").setId(uuid)
				.signWith(getSignInKey(), SignatureAlgorithm.HS512).compact();

		return new String[] { accessToken, refreshToken };
	}

	public boolean isTokenValid(String token, UserDetails userDetails) {
		final String username = extractUsername(token);
		return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
	}

	private boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}

	private Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}

	private Claims extractAllClaims(String token) {
		return Jwts.parserBuilder().setSigningKey(getSignInKey()).build().parseClaimsJws(token).getBody();
	}

	private Key getSignInKey() {
		byte[] keyBytes = Decoders.BASE64.decode(secretKey);
		return Keys.hmacShaKeyFor(keyBytes);
	}

	public boolean validateJwtToken(String authToken) {
		try {
			String username = extractClaim(authToken, Claims::getSubject);
			if (!extractClaim(authToken, Claims::getId).equals(this.jwtTocketIds.get(username))) {
				log.error("Tocken Mismatched");
				throw new MalformedJwtException("Tocken Mismatched");
			}
			if (Boolean.TRUE.equals(isTokenExpired(authToken)))
				throw new ExpiredJwtException(null, null, authToken);
			return true;
		} catch (MalformedJwtException e) {
			log.error("Invalid JWT token: {}", e.getMessage());
			throw e;
		} catch (ExpiredJwtException e) {
			log.error("JWT token is expired: {}", e.getMessage());
			throw e;
		} catch (UnsupportedJwtException e) {
			log.error("JWT token is unsupported: {}", e.getMessage());
			throw e;
		} catch (IllegalArgumentException e) {
			log.error("JWT claims string is empty: {}", e.getMessage());
			throw e;
		}
	}
}
