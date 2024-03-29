package com.kafkamgt.uiapi.repository;

import com.kafkamgt.uiapi.dao.KwClusterID;
import com.kafkamgt.uiapi.dao.KwClusters;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface KwClusterRepo extends CrudRepository<KwClusters, KwClusterID> {
    List<KwClusters> findAllByClusterTypeAndTenantId(String type, int tenantId);

    @Query(value ="select max(clusterid) from kwclusters where tenantid = :tenantId", nativeQuery = true)
    Integer getNextClusterId(@Param("tenantId") Integer tenantId);

    List<KwClusters>  findAllByTenantId(int tenantId);
}
