package com.authservice.authserviceoauth2.component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationToken;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;


import java.io.IOException;

@Component
public class CustomOidcLogoutSuccessHandler implements LogoutSuccessHandler {

    private static final String POST_LOGOUT_REDIRECT_URI = "post_logout_redirect_uri";

    private static final OAuth2TokenType ID_TOKEN = new OAuth2TokenType("id_token");

    private final OAuth2AuthorizationService authorizationService;

    public CustomOidcLogoutSuccessHandler(OAuth2AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                                Authentication authentication) throws IOException, ServletException {

        if (authentication instanceof OidcLogoutAuthenticationToken oidcLogoutToken) {
            String idTokenHint = oidcLogoutToken.getIdTokenHint();
            OAuth2Authorization authorization = authorizationService.findByToken(idTokenHint, ID_TOKEN);

            if (authorization != null) {
                System.out.println("Revoking tokens for ID Token: " + idTokenHint);
                authorizationService.remove(authorization);
            }
        }

        // ✅ Invalidate session
        request.getSession(false); // Avoid creating a new session
        if (request.getSession(false) != null) {
            request.getSession().invalidate();
        }

        // ✅ Clear JSESSIONID cookie
        Cookie cookie = new Cookie("JSESSIONID", null);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(0);
        response.addCookie(cookie);

        // Continue redirecting to post_logout_redirect_uri
        String redirectUri = request.getParameter(POST_LOGOUT_REDIRECT_URI
        );
        if (redirectUri != null) {
            response.sendRedirect(redirectUri);
        } else {
            response.setStatus(HttpServletResponse.SC_OK);
        }
    }
}
