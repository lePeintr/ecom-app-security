package com.example.securiity_service.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Cette classe TestRestAPI représente le test de la configuration de sprig boot security par defaut
 *Il s'agit d'une Securite statefull basé sur les sessions et cookies
 *
 * On ajoute le paramètre Authentication pour tester apres avoir fait le test de l'accesToken que tout est ok
 *
 * @PreAuthorize permet de tester l'authorisation d'acces au methode demandee par la requete en fonction du role de l'utilisateur(proetger
 * les methodes avec un role) avec @PreAutothorize il faut ajouter @EnableGlobalMethodSecurity(prePostEnabled = true) dans SecurityServiceApplication
 * On peut faire cette protection dans le controlleur ou dans la couche service
 * @author Utilisateur
 * @version 1.0
 */
@RestController
public class TestRestAPI {
    @GetMapping("/dataTest")
    @PreAuthorize("hasAuthority('SCOPE_USER')")
    public Map<String, Object> dataTest(Authentication authentication){
        return Map.of(
                "message","data test",
                "username",authentication.getName(),
                "authorities",authentication.getAuthorities()
        );
    }
    @PostMapping("/saveData")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public Map<String,String> saveData(String data){
        return Map.of("dataSaved",data);
    }
}
