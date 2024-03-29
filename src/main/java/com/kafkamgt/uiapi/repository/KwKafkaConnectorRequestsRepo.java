package com.kafkamgt.uiapi.repository;

import com.kafkamgt.uiapi.dao.KafkaConnectorRequest;
import com.kafkamgt.uiapi.dao.KafkaConnectorRequestID;
import com.kafkamgt.uiapi.dao.TopicRequest;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface KwKafkaConnectorRequestsRepo extends CrudRepository<KafkaConnectorRequest, KafkaConnectorRequestID> {
    Optional<KafkaConnectorRequest> findById(KafkaConnectorRequestID connectorRequestId);

    List<KafkaConnectorRequest> findAllByConnectorStatusAndTenantId(String connectorStatus, int tenantId);

    List<KafkaConnectorRequest> findAllByConnectortypeAndTenantId(String connectorType, int tenantId);

    List<KafkaConnectorRequest> findAllByConnectorStatusAndConnectorNameAndEnvironmentAndTenantId(String connectorStatus,
                                                                                                  String connectorName, String envId,
                                                                                                  int tenantId);

    @Query(value ="select count(*) from kwkafkaconnectorrequests where env = :envId and tenantid = :tenantId and connectorstatus='created'", nativeQuery = true)
    List<Object[]> findAllConnectorRequestsCountForEnv(@Param("envId") String envId, @Param("tenantId") Integer tenantId);

    @Query(value ="select max(connectorid) from kwkafkaconnectorrequests where tenantid = :tenantId", nativeQuery = true)
    Integer getNextConnectorRequestId(@Param("tenantId") Integer tenantId);

    @Query(value ="select count(*) from kwkafkaconnectorrequests where teamid = :teamId and tenantid = :tenantId and connectorstatus='created'",
            nativeQuery = true)
    List<Object[]> findAllRecordsCountForTeamId(@Param("teamId") Integer teamId, @Param("tenantId") Integer tenantId);

    List<KafkaConnectorRequest> findAllByTenantId(int tenantId);
}
