# EUDI Core Authorization Server

This is an implementation of the core functionalities of an authorization server. It is designed to reside on the authentic source side.

To use it, you first have to add it in the ```pom.xml``` file, then extend the following classes:

- `BaseUser`
- `BaseUserDetails` (`@Entity`)
- `BaseUserRepository<User>` (`@Repository`)
- `BaseUserDetailsService` (`@Service`)

Then, you have to add the following lines above your Spring Boot main function:

```java
@SpringBootApplication(scanBasePackages = {
        "ro.mta.implauthzserver",
        "ro.mta.baseauthzserver"
})
@EntityScan(basePackages = {
        "ro.mta.implauthzserver.entity",
        "ro.mta.baseauthzserver.entity"
})
@EnableJpaRepositories(basePackages = {
        "ro.mta.implauthzserver.repository",
        "ro.mta.baseauthzserver.repository"
})
```
Lastly, if you don't want to use the default HTML templates, you have to add the new ones in the `main/java/resources/templates` folder of your project. The templates offered by default are:

- `login.html`
- `consent.html`
- `error.html`

If you only want to change the logo showed on the `consent` page, you can add your desired picture in the `main/java/resources/static` with the name `logo.png`.