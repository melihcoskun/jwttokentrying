package com.coskun.jwttoken.service;

import com.coskun.jwttoken.entity.User;
import com.coskun.jwttoken.payload.AuthenticationRequest;
import com.coskun.jwttoken.payload.AuthenticationResponse;
import com.coskun.jwttoken.payload.RegisterRequest;
import com.coskun.jwttoken.repository.UserRepository;
import io.jsonwebtoken.security.Password;
import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest registerRequest){

        User user = User.builder()
                .firstName(registerRequest.getFirstName())
                .lastName(registerRequest.getLastName())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .role(registerRequest.getRole())
                .build();

        User savedUser = userRepository.save(user);
        String jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse.builder().accessToken(jwtToken).build();

    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        //First Step

        // we need to validate our request (validate whether password and username is corret)
        // Verify whether user present in the database
        // Which AuthenticationProvider -> DaoAuthenticationProver(Iject)
        // We need to authenticate using authenticationManager injecting this authenticationProvider

        // Second Step

        // Verify whether userName and password is correct -> UserNamePasswordAuthenticationToken
        // verify whether user present in db
        // generate token
        // return the token
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    request.getEmail(),
                        request.getPassword()
                )

        );
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();
        String jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse.builder().accessToken(jwtToken).build();

    }
}
