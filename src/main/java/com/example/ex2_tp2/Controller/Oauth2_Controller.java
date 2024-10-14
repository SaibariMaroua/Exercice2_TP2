package com.example.ex2_tp2.Controller;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.PostMapping;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class Oauth2_Controller {
    private final AuthenticationManager authenticationManager;
    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final UserDetailsService userDetailsService;

    public Oauth2_Controller(AuthenticationManager authenticationManager, JwtEncoder jwtEncoder, JwtDecoder jwtDecoder, UserDetailsService userDetailsService) {
        this.authenticationManager = authenticationManager;
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.userDetailsService = userDetailsService;
    }

    @PostMapping("/login")
    public Map<String, String> login( String username,  String password){

        // vérifier authentication
        Authentication authenticate = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        // générer les tokens
        Instant instant = Instant.now();

        // recupérer Scopes de l'utilisateur
        String scopes =  authenticate.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(" "));

        JwtClaimsSet jwtClaimsSet_Access_token =  JwtClaimsSet.builder()
                .issuer("MS_sec")
                .subject(authenticate.getName())
                .issuedAt(instant)
                .expiresAt(instant.plus(2, ChronoUnit.MINUTES))
                .claim("name",authenticate.getName())
                .claim("SCOPE",scopes)
                .build();

        // Signée le token
        String Access_Token = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet_Access_token)).getTokenValue();

        // refresh Token
        JwtClaimsSet jwtClaimsSet_refresh_token =  JwtClaimsSet.builder()
                .issuer("MS_sec")
                .subject(authenticate.getName())
                .issuedAt(instant)
                .expiresAt(instant.plus(15, ChronoUnit.MINUTES))
                .claim("name",authenticate.getName())
                .build();
        String RefreshToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet_refresh_token)).getTokenValue();

        Map<String, String> ID_Token = new HashMap<>();

        ID_Token.put("Access_Token",Access_Token);
        ID_Token.put("Refresh_Token",RefreshToken);

        return ID_Token;
    }

    @PostMapping("/RefreshToken")
    public  Map<String,String> fr_t(String RefreshToken){

        if(RefreshToken==null){
            return Map.of("Message error","Refresh_Token est necessaite");
        }

        // vérifer la sig
        Jwt decoded = jwtDecoder.decode(RefreshToken);

        String  username = decoded.getSubject();

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        // renouveller
        Instant instant = Instant.now();

        String scopes =  userDetails.getAuthorities().stream().map(auth -> auth.getAuthority()).collect(Collectors.joining(" "));

        JwtClaimsSet jwtClaimsSet_Access_token =  JwtClaimsSet.builder()
                .issuer("MS_sec")
                .subject(userDetails.getUsername())
                .issuedAt(instant)
                .expiresAt(instant.plus(2, ChronoUnit.MINUTES))
                .claim("name",userDetails.getUsername())
                .claim("SCOPE",scopes)
                .build();
        String Access_Token = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet_Access_token)).getTokenValue();

        Map<String, String> ID_Token = new HashMap<>();
        ID_Token.put("Access_Token",Access_Token);
        ID_Token.put("Refresh_Token",RefreshToken);

        return ID_Token;

    }
}