package com.wissem.auth;

import com.wissem.config.JwtService;
import com.wissem.user.Role;
import com.wissem.user.UserRepository;
import lombok.RequiredArgsConstructor;
import com.wissem.user.User;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class AuthenticationService {

  private final UserRepository userRepo;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final AuthenticationManager authenticationManager;

  public AuthenticationResponse register(RegisterRequest request) {
    var user = User.builder()
        .firstname(request.getFirstname())
        .lastname(request.getLastname())
        .email(request.getEmail())
        .password(passwordEncoder.encode(request.getPassword()))
        .role(Role.USER)
        .build();
    userRepo.save(user);

    var token = jwtService.generateToken(user);
    return AuthenticationResponse.builder()
        .token(token)
        .build();
  }

  public AuthenticationResponse login(LoginRequest request) {
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            request.getEmail(),
            request.getPassword()
        )
    );
    var user = userRepo.findByEmail(request.getEmail()).orElseThrow();
    var token = jwtService.generateToken(user);
    return AuthenticationResponse.builder()
        .token(token)
        .build();
  }
}
