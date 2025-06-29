package ro.mta.baseauthzserver.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import ro.mta.baseauthzserver.controller.UserInfoController;
import ro.mta.baseauthzserver.entity.CoreUser;
import ro.mta.baseauthzserver.repository.CoreUserRepository;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Service
@Slf4j
public class UserInfoService {

    private static final Logger logger = LoggerFactory.getLogger(UserInfoController.class);

    private final CoreUserRepository coreUserRepository;

    private final ObjectMapper objectMapper;

    private final Set<String> excludedFields = Set.of(
            "password", "credentials", "authorities", "accountNonExpired",
            "accountNonLocked", "credentialsNonExpired", "enabled", "id", "roles", "role"
    );
    
    public UserInfoService(@Autowired(required = false) CoreUserRepository coreUserRepository) {
        this.coreUserRepository = coreUserRepository;
        this.objectMapper = new ObjectMapper();
    }

    public Map<String, Object> getUserInfo(final String username) {
        if (coreUserRepository == null) {
            throw new IllegalStateException("No CoreUserRepository implementation found");
        }
        

        Optional<CoreUser> userOpt = coreUserRepository.findByUsername(username);

        if (userOpt.isEmpty()) {
            logger.warn("User not found: {}", username);
            return null;
        }

        CoreUser user = userOpt.get();

        logger.debug("UserInfo request for user: {}", user.getUsername());

        Map<String, Object> userInfo = convertToMapUsingJackson(user);

        if (userInfo.isEmpty()) {
            logger.error("UserInfo request for user {} not found", username);
            return null;
        }

        removeSensitiveFields(userInfo);

        return userInfo;
    }


    private Map<String, Object> convertToMapUsingJackson(Object user) {
        try {
            String json = objectMapper.writeValueAsString(user);
            TypeReference<Map<String, Object>> typeRef = new TypeReference<Map<String, Object>>() {};
            return objectMapper.readValue(json, typeRef);
        } catch (Exception e) {
            log.error("Failed to convert user to map using Jackson", e);
            return null;
        }
    }

    /**
     * Remove sensitive fields that shouldn't be exposed
     */
    private void removeSensitiveFields(Map<String, Object> userInfo) {
        excludedFields.forEach(userInfo::remove);
    }


}
