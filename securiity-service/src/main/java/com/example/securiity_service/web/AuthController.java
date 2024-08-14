package com.example.securiity_service.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Cette classe AuthController représente la classe pour gener un token
 *
 * @author Utilisateur
 * @version 1.0
 */
@RestController
public class AuthController {
    private JwtEncoder jwtEncoder;
    private JwtDecoder jwtDecoder;

    private AuthenticationManager authenticationManager;
    private UserDetailsService userDetailsService;

    public AuthController(JwtEncoder jwtEncoder,AuthenticationManager authenticationManager,JwtDecoder jwtDecoder,UserDetailsService userDetailsService) {
        this.jwtEncoder = jwtEncoder;
        this.authenticationManager=authenticationManager;
        this.jwtDecoder = jwtDecoder;
        this.userDetailsService=userDetailsService;
    }

    /**
     * Cette methode permer de generer un token
     * on passe en parametre l'objet authentication car on utilise une authentification basique
     * Authentification basique veut dire que dans la requete http on envoie le username et password ,
     * et après Spring Security va authentifier  doc c'est Spring security qui gère l'authentification dans ce cas
     *
     * NB: l'authentification basique n'est pas bon ni conseillé a utiliser car a chaque fois qu'on envoie une requete
     * on envoie le username et le password ou il faut envoyer le token quand on fait la requete:test dans postman
     * @return
     */

    /**
     * Cas de l'authentification basique
     * @param authentication
     * @return
     */
    //@PostMapping("/token")
/*
    public Map<String,String> jwtToken(Authentication authentication){
        Map<String,String> idToken = new HashMap<>();
        Instant instant = Instant.now();
        //scope va contenir l'ensemble des roles de l'utilisateur séparé par les espaces
        String scope =  authentication.getAuthorities()
                .stream().map(auth->auth.getAuthority()).collect(Collectors.joining(" "));//(Collectors.joining()) recupere les authotiry les convertis en chaine de caractere separes par les espaces separe
        JwtClaimsSet jwtClaimsSet=JwtClaimsSet.builder()
                .subject(authentication.getName()) //subject represente le username
                .issuedAt(instant) //represente la date à la quelle le token est créé
                .expiresAt(instant.plus(5, ChronoUnit.MINUTES))//date expiration du token qu'on va generer(5 minutes apres la date de creation)
                .issuer("security-service") //l'application qui a généré le token
                .claim("scope",scope) //les roles de l'utilisateurs dans le token
                .build();

        String jwtAccessToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
        idToken.put("accessToken",jwtAccessToken);
        return idToken;
    }
*/

    /**
     * Cas de l'authentification personnalisée
     * @Param grantType
     * @param username
     * @param password
     * @Param withRefreshToken
     * @Param refreshToken
     * @return
     */
    @PostMapping("/token")
    public ResponseEntity<Map<String,String>> jwtTokenPersonnalise(
            String grantType,
            String username,
            String password,
            boolean withRefreshToken,
            String refreshToken){
        String subject=null;
        String scope=null;

        //authentification avec le password
        if(grantType.equals("password")){
             Authentication authentication =  authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username,password)
            );
             subject= authentication.getName();
             scope=authentication.getAuthorities()
                     .stream().map(auth->auth.getAuthority()).collect(Collectors.joining(" "));
        }
        //Authentification avec le refreshToken

        else if(grantType.equals("refreshToken")){
            if(refreshToken==null){
                return new ResponseEntity<>(Map.of("errorMessage","Refresh Token is Required"), HttpStatus.UNAUTHORIZED);
            }
            Jwt decodeJWT = null;
            try {
                decodeJWT =  jwtDecoder.decode(refreshToken);
            } catch (JwtException e) {
                return new ResponseEntity<>(Map.of("errorMessage",e.getMessage()), HttpStatus.UNAUTHORIZED);
            }
            //String subject = decodeJWT.getSubject(); //recupere l'username
            subject= decodeJWT.getSubject();
             UserDetails userDetails= userDetailsService.loadUserByUsername(subject);
            Collection<? extends GrantedAuthority> authorities= userDetails.getAuthorities();//on recupere les scope/role en fonction de l'userName
            //String scope = authorities.stream().map(auth->auth.getAuthority()).collect(Collectors.joining(""));
            scope = authorities.stream().map(auth->auth.getAuthority()).collect(Collectors.joining(" "));
        }

        Map<String,String> idToken = new HashMap<>();
        Instant instant = Instant.now();
        //scope va contenir l'ensemble des roles de l'utilisateur séparé par les espaces
      /*  String scope =  authentication.getAuthorities()
                .stream().map(auth->auth.getAuthority()).collect(Collectors.joining(" "));*///(Collectors.joining()) recupere les authotiry les convertis en chaine de caractere separes par les espaces separe
        JwtClaimsSet jwtClaimsSet=JwtClaimsSet.builder()
                //.subject(authentication.getName()) //subject represente le username
                .subject(subject)
                .issuedAt(instant) //represente la date à la quelle le token est créé
                .expiresAt(instant.plus(withRefreshToken?1:5, ChronoUnit.MINUTES))//date expiration du token qu'on va generer(5 minutes apres la date de creation)
                .issuer("security-service") //l'application qui a généré le token
                .claim("scope",scope) //les roles de l'utilisateurs dans le token
                .build();

        String jwtAccessToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
        idToken.put("accessToken",jwtAccessToken);
        if(withRefreshToken){
            JwtClaimsSet jwtClaimsSetRefresh=JwtClaimsSet.builder()
                    .subject(subject) //subject represente le username
                    .issuedAt(instant) //represente la date à la quelle le token est créé
                    .expiresAt(instant.plus(5, ChronoUnit.MINUTES))//date expiration du token qu'on va generer(5 minutes apres la date de creation)
                    .issuer("security-service") //l'application qui a généré le token
                    .build();
            String jwtRefreshToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSetRefresh)).getTokenValue();
            idToken.put("refreshToken",jwtRefreshToken);
        }
        return new ResponseEntity<>(idToken,HttpStatus.OK);
    }
}
