package ro.mta.baseauthzserver.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;


@Setter
@Getter
@Component
@ConfigurationProperties(prefix = "baseauthzserver")
public class AuthzProperties {

    // Main getters and setters
    private Templates templates = new Templates();
    @Setter
    @Getter
    public static class Templates {
        private String location = "classpath:templates/";
        private boolean enableExternal = true;
        private String externalLocation = "file:./templates/";

    }
}