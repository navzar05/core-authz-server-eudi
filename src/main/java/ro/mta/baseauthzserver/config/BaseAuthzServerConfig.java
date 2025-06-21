package ro.mta.baseauthzserver.config;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;


@AutoConfiguration
@EnableConfigurationProperties(BaseAuthzServerConfig.class)
@ComponentScan(basePackages = "ro.mta.baseauthzserver")
@Import({
        ThymeleafConfig.class,
        AuthorizationServerConfig.class,
        ControllerConfig.class,
        SessionConfig.class,
})
public class BaseAuthzServerConfig {
}