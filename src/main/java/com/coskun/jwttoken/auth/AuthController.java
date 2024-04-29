package com.coskun.jwttoken.auth;


import com.coskun.jwttoken.payload.AuthenticationRequest;
import com.coskun.jwttoken.payload.AuthenticationResponse;
import com.coskun.jwttoken.payload.RegisterRequest;
import com.coskun.jwttoken.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/crackit/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest registerRequest) {

        AuthenticationResponse authResponse = authService.register(registerRequest);
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request
            ) {


        return new ResponseEntity<>(authService.authenticate(request), HttpStatus.CREATED);

    }

}
