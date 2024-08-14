package com.example.customer_service;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Cette classe CustomerRestAPI représente ...
 *
 * @author Utilisateur
 * @version 1.0
 */
@RestController
public class CustomerRestAPI {
    @GetMapping("/customers")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public Map<String,Object> customer(Authentication authentication){
        return Map.of("name","vini","email","vini@madrid.com",
                "username",authentication.getName(),
                "scope",authentication.getAuthorities());
    }
}
