package com.authguard.usecases.repository;

public record CustomerGrowthJobQueryCriteria(
    String workspaceId, String projectId, String status, String ownerUserId) {}
