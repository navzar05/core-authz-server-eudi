# EUDI Core Authorization Server

This is an implementation of the core functionalities of an authorization server. It is designed to reside on the authentic source side.

First of all, you need to add this in your `pom.xml` file:
```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>
```
And, in the `<dependencies>` group, add:
```xml
<dependency>
    <groupId>com.github.navzar05</groupId>
    <artifactId>core-authz-server-eudi</artifactId>
    <version>1.0.0</version>
</dependency>
```
Note that the version tag needs to be changed accordingly to the latest release.

The next step is to implement the following interfaces of the `core-authz-server-eudi`:

- `BaseUser`
- `BaseUserDetails` (`@Entity`)
- `BaseUserRepository<User>` (`@Repository`)
- `BaseUserDetailsService` (`@Service`)

After that, you have to add the following lines above your Spring Boot main function:

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
Now, the server is ready to go. If you don't want to use the default HTML templates, you have to add the new ones in the `main/java/resources/templates` folder of your project. The templates offered by default are:

- `login.html`
- `consent.html`
- `error.html`

If you only want to change the logo showed on the `consent` page, you can add your desired picture in the `main/java/resources/static` with the name `logo.png`.