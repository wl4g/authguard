package com.authguard.usecases.dto;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record CustomerGrowthJobDto(
    Long id,
    String region,
    String tenantId,
    String workspaceId,
    String projectId,
    String jobId,
    String displayName,
    String status,
    String ownerUserId) {}
