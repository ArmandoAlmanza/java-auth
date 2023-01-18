package com.armando.Auth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.armando.User.User;
import com.armando.Config.JwtService;
import com.armando.User.Role;
import com.armando.User.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.var;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final AuthenticationManager authenticationManager;

	public AuthenticationResponse register(RegisterRequest req) {
		var user = User.builder()
				.firstName(req.getFirstName())
				.lastName(req.getLastName())
				.email(req.getEmail())
				.password(passwordEncoder.encode(req.getPassword()))
				.role(Role.USER)
				.build();
		userRepository.save(user);
		var jwt = jwtService.generateToken(user);
		return AuthenticationResponse.builder().token(jwt).build();
	}

	public AuthenticationResponse authenticate(AuthenticationRequest req) {
		authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(
						req.getEmail(),
						req.getPassword()));
		var user = userRepository.findByEmail(req.getEmail()).orElseThrow();
		var jwt = jwtService.generateToken(user);
		return AuthenticationResponse.builder().token(jwt).build();
	}

}
