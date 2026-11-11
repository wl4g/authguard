package com.authguard.usecases.dto;

public record CustomerGrowthJobSearchRequest(
    String workspaceId, String projectId, String status, String ownerUserId) {}
