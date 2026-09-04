package com.authguard.usecases.entity;

public record CustomerGrowthJobEntity(
    Long id,
    String region,
    String tenantId,
    String workspaceId,
    String projectId,
    String jobId,
    String displayName,
    String status,
    String ownerUserId) {}
