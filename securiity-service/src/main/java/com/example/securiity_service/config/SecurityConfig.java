package com.example.securiity_service.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Cette classe SecurityConfig représente la classe de configuration de securite
 *Securité stateless base sur le JWT
 * @author Utilisateur
 * @version 1.0
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private RsaKeysConfig rsaKeysConfig;

    private PasswordEncoder passwordEncoder;
    public SecurityConfig(RsaKeysConfig rsaKeysConfig,PasswordEncoder passwordEncoder) {
        this.rsaKeysConfig = rsaKeysConfig;
        this.passwordEncoder=passwordEncoder;
    }

    /**
     * Ancienne technique pas recommendé : Le bean est en commentaire donc la methode aussi n'est pas utilisée dans le code
     * @param authenticationConfiguration
     * @return
     * @throws Exception
     */
    //@Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService){
        var authProvider = new DaoAuthenticationProvider();
        authProvider.setPasswordEncoder(passwordEncoder); //on met le password qu'on veut utiliser
        authProvider.setUserDetailsService(userDetailsService);
        return new ProviderManager(authProvider);

    }
    /**
     * On defini les utilisateur qui ont droit d'acceder à l'application
     * pour le password on peut utiliser le password encoder a l'aide du plugin base64 helper(installer le plugin, click droit sur le string
     * a encoder et choisir base 64)
     * @return
     */
    @Bean
    public UserDetailsService inMemoryUserDetailsManager(){
         return new InMemoryUserDetailsManager(
                 User.withUsername("user1").password("{noop}MTIzNA==").authorities("USER").build(),//encodage avec le plugin
                 User.withUsername("user2").password(passwordEncoder.encode("1234")).authorities("USER").build(),//encodage avecc le PassxordEncoder
                 User.withUsername("admin").password(passwordEncoder.encode("1234")).authorities("USER","ADMIN").build()
         );
    }

    /**
     * On specifie qu'il faut une authentification pour toutes les requetes qui sont envoyees
     * @param httpSecurity
     * @return
     * @throws Exception
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(csrf->csrf.disable())
                .authorizeRequests(auth->auth.requestMatchers("/token/**").permitAll())//Authoriser l'acces à tous les endPoint /token/**
                .authorizeRequests(auth-> auth.anyRequest().authenticated()) //pour toutes les requetes on a besoin d'etre authentifié
                .sessionManagement(sess->sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))//Generer un token de type jwt
                .httpBasic(Customizer.withDefaults())
                .build();
    }

    /**
     * Pour verifier la signatue on a juste besoin de public key
     * @return
     */
    @Bean
    public JwtDecoder jwtDecoder(){
        return NimbusJwtDecoder.withPublicKey(rsaKeysConfig.publicKey()).build();
    }

    /**
     * Pour signer le token on a besoin de public key et private key
     * @return
     */
    @Bean
    public JwtEncoder jwtEncoder(){
        JWK jwk = new RSAKey.Builder(rsaKeysConfig.publicKey()).privateKey(rsaKeysConfig.privateKey()).build();
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwkSource);
    }

}
