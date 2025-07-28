package com.authservice.authserviceoauth2.service;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.util.List;

public class CustomJdbcOAuth2AuthorizationService extends JdbcOAuth2AuthorizationService {

    private final JdbcTemplate jdbcTemplate;
    private final RegisteredClientRepository registeredClientRepository;

    public CustomJdbcOAuth2AuthorizationService(JdbcTemplate jdbcTemplate,
                                                RegisteredClientRepository registeredClientRepository) {
        super(jdbcTemplate, registeredClientRepository);
        this.jdbcTemplate = jdbcTemplate;
        this.registeredClientRepository = registeredClientRepository;
    }

    public List<OAuth2Authorization> findByPrincipalName(String principalName) {
        System.out.println("[CustomJdbcOAuth2AuthorizationService] Looking for authorizations with principal: " + principalName);

        String sql = "SELECT * FROM oauth2_authorization WHERE principal_name = ?";
        OAuth2AuthorizationRowMapper rowMapper = new OAuth2AuthorizationRowMapper(this.registeredClientRepository);
        List<OAuth2Authorization> list = jdbcTemplate.query(sql, rowMapper, principalName);

        System.out.println("[CustomJdbcOAuth2AuthorizationService] Found " + list.size() + " records");
        return list;
    }

}
