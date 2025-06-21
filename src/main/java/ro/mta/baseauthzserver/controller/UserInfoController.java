package ro.mta.baseauthzserver.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PathVariable;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ro.mta.baseauthzserver.service.UserInfoService;

import java.util.Map;

/**
 * Controller for OIDC UserInfo endpoint
 */
@RestController
@RequestMapping("/service")
@Slf4j
public class UserInfoController {
    //TODO: De separat controller de service
    private static final Logger logger = LoggerFactory.getLogger(UserInfoController.class);
    private final UserInfoService userInfoService;


    public UserInfoController(UserInfoService userInfoService) {
        this.userInfoService = userInfoService;
    }

    @GetMapping("/userinfo/{username}")
    @PreAuthorize("hasAuthority('SCOPE_issuer:credentials')")
    public ResponseEntity<Map<String, Object>> getServiceUserInfo(
            @PathVariable("username") String username,
            Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof Jwt jwt)) {
            logger.error("Invalid authentication - not a JWT");
            return ResponseEntity.badRequest().build();
        }
        String clientId = jwt.getSubject();
        logger.debug("Request from client: {}", clientId);

        if (!"issuer-srv".equals(clientId)) {
            logger.warn("Unauthorized client: {}", clientId);
            return ResponseEntity.status(403).build();
        }

        Map<String, Object> userInfo = this.userInfoService.getUserInfo(username);

        if (userInfo == null) {
            return ResponseEntity.status(404).build();
        }
        return ResponseEntity.ok(
                userInfo
        );

    }

}