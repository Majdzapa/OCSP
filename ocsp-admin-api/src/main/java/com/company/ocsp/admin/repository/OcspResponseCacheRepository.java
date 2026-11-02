package com.company.ocsp.admin.repository;

import com.company.ocsp.admin.model.OcspResponseCache;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;

@Repository
public interface OcspResponseCacheRepository extends JpaRepository<OcspResponseCache, String> {

    /** Delete expired entries — called by a scheduled cleanup job. */
    @Modifying
    @Query("DELETE FROM OcspResponseCache c WHERE c.nextUpdate < :now")
    int deleteExpired(Instant now);
}
