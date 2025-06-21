package ro.mta.baseauthzserver.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.NoRepositoryBean;
import ro.mta.baseauthzserver.entity.BaseUser;

import java.util.Optional;

/**
 * Base repository interface for EUDI users
 */
@NoRepositoryBean
public interface BaseUserRepository<T extends BaseUser> extends JpaRepository<T, Long> {

    Optional<T> findByUsername(String username);

    Optional<T> findByEmail(String email);
}