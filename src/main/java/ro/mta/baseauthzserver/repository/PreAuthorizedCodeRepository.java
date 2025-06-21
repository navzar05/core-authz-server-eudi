package ro.mta.baseauthzserver.repository;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import ro.mta.baseauthzserver.entity.PreAuthorizedCode;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface PreAuthorizedCodeRepository extends JpaRepository<PreAuthorizedCode, String> {
    Optional<PreAuthorizedCode> findByCodeAndUsedFalseAndExpiresAtAfter(String code, Instant now);
    Optional<PreAuthorizedCode> findByCodeAndUsedFalse(String code);
    Optional<PreAuthorizedCode> findByCode(String code);
    void deleteByExpiresAtBefore(Instant now);
}