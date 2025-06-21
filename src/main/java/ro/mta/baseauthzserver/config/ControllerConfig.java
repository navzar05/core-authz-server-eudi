package ro.mta.baseauthzserver.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;


@Configuration
@ComponentScan(basePackages = "ro.mta.baseauthzserver.controller")
public class ControllerConfig {
}