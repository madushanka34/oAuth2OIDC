//package com.authservice.authserviceoauth2.controller;
//
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
//import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
//import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
//import org.springframework.web.bind.annotation.*;
//
//import java.net.URI;
//import java.util.Map;
//
//
//@RestController
//public class LogoutController {
//
//    private final OAuth2AuthorizationService authorizationService;
//
//    public LogoutController(OAuth2AuthorizationService authorizationService) {
//        this.authorizationService = authorizationService;
//    }
//
//    @PostMapping("/api/logout")
//    public ResponseEntity<Void> revokeAccessToken(@RequestBody Map<String, String> body) {
//        String token = body.get("token");
//
//        System.out.println("Received logout request for token: " + token);
//        if (token == null || token.isBlank()) {
//            return ResponseEntity.badRequest().build();
//        }
//
//        OAuth2Authorization authorization = authorizationService.findByToken(
//                token,
//                OAuth2TokenType.ACCESS_TOKEN
//        );
//
//        if (authorization != null) {
//            System.out.println("Authorization found, removing...");
//            authorizationService.remove(authorization);
//        } else {
//            System.out.println("Authorization not found for token.");
//        }
//
//        return ResponseEntity.ok().build();
//    }
//}
