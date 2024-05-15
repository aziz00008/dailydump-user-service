package com.example.dailydumpuserservice.service;

import com.example.dailydumpuserservice.config.JwtService;
import com.example.dailydumpuserservice.controller.AuthenticationRequest;
import com.example.dailydumpuserservice.controller.AuthenticationResponse;
import com.example.dailydumpuserservice.controller.RegisterRequest;
import com.example.dailydumpuserservice.model.Role;
import com.example.dailydumpuserservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;

import com.example.dailydumpuserservice.model.User;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;
    private  final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    public AuthenticationResponse register(RegisterRequest request){
  var user = User.builder().username(request.getUsername()).password(passwordEncoder.encode(request.getPassword())).role(Role.USER).build();
  repository.save(user);
  var jwtToken =jwtService.generateToken(user);

  return AuthenticationResponse.builder().token(jwtToken).build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request){
//authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(),request.getPassword()));
/*User user = User.builder().build();
user.setUsername("azizou");
user.setPassword("zebi");
user.setRole(Role.valueOf("USER"));*/
        User user = repository.findByUsername(request.getUsername());
        var jwtToken =jwtService.generateToken(user);
        return AuthenticationResponse.builder().token(jwtToken).build();
    }
}
