package com.kafkamgt.uiapi.controller;

import com.kafkamgt.uiapi.model.JwtRequest;
import com.kafkamgt.uiapi.model.JwtResponse;
import com.kafkamgt.uiapi.service.JwtTokenUtilService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("/")
public class JwtAuthenticationController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenUtilService jwtTokenUtil;

    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
    public ResponseEntity<JwtResponse> createAuthenticationToken(@Valid @RequestBody JwtRequest authenticationRequest) throws Exception {
        authenticate(authenticationRequest.getUsername(), authenticationRequest.getPassword());
        final UserDetails userDetails = (UserDetails) authenticationManager.authenticate(new UsernamePasswordAuthenticationToken
                (authenticationRequest.getUsername(), authenticationRequest.getPassword()))
                .getPrincipal();

        final String token = jwtTokenUtil.generateToken(userDetails);
        return ResponseEntity.ok(new JwtResponse(token));
    }

    @RequestMapping(value = "/refreshSession", method = RequestMethod.POST)
    public ResponseEntity<?> refreshSession(@RequestBody JwtRequest authenticationRequest) throws Exception {
        authenticate(authenticationRequest.getUsername(), authenticationRequest.getPassword());

        final UserDetails userDetails = (UserDetails) authenticationManager.authenticate(new UsernamePasswordAuthenticationToken
                (authenticationRequest.getUsername(), authenticationRequest.getPassword()))
                .getPrincipal();

        final String token = jwtTokenUtil.generateToken(userDetails);
        return ResponseEntity.ok(new JwtResponse(token));
    }

    @RequestMapping(value = "/isValidToken", method = RequestMethod.GET)
    public ResponseEntity<Boolean> isValidToken() throws Exception {

        return new ResponseEntity<>(true, HttpStatus.OK);
    }

    private void authenticate(String username, String password) throws Exception {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException e) {
            throw new Exception("USER_DISABLED", e);
        } catch (BadCredentialsException e) {
            throw new Exception("INVALID_CREDENTIALS", e);
        }
    }
}
