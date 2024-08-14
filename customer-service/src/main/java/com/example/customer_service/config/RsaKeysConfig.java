package com.example.customer_service.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Cette classe RsaKeysConfig représente la classe pour recupere les valeurs des clés données dans les properties
 *Varecuperer dans le fichier application.properties les variables qui commencene par rsa et vient les injecter dans les variablesen parametres
 *
 * NB: Si @Configuartion properties signale une erreur,
 * ajouter @EnableConfigurationProperties dans SecurityServiceApplication(RsaKeysConfig.class)
 * @author Utilisateur
 * @version 1.0
 */
@ConfigurationProperties(prefix= "rsa")
public record RsaKeysConfig(RSAPublicKey publicKey){
}
