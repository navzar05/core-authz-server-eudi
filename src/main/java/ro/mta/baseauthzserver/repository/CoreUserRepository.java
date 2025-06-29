package ro.mta.baseauthzserver.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.NoRepositoryBean;
import ro.mta.baseauthzserver.entity.CoreUser;

import java.util.Optional;

/**
 * Base repository interface for EUDI users
 */
@NoRepositoryBean
public interface CoreUserRepository<T extends CoreUser> extends JpaRepository<T, Long> {

    Optional<T> findByUsername(String username);

    Optional<T> findByEmail(String email);
}