package com.authguard.usecases.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "e2e_authguard_customer_growth_jobs")
public class CustomerGrowthJobEntity {
  @Id private Long id;

  private String region;

  @Column(name = "tenant_id")
  private String tenantId;

  @Column(name = "workspace_id")
  private String workspaceId;

  @Column(name = "project_id")
  private String projectId;

  @Column(name = "job_id")
  private String jobId;

  @Column(name = "display_name")
  private String displayName;

  private String status;

  @Column(name = "owner_user_id")
  private String ownerUserId;

  protected CustomerGrowthJobEntity() {}

  public CustomerGrowthJobEntity(
      Long id,
      String region,
      String tenantId,
      String workspaceId,
      String projectId,
      String jobId,
      String displayName,
      String status,
      String ownerUserId) {
    this.id = id;
    this.region = region;
    this.tenantId = tenantId;
    this.workspaceId = workspaceId;
    this.projectId = projectId;
    this.jobId = jobId;
    this.displayName = displayName;
    this.status = status;
    this.ownerUserId = ownerUserId;
  }

  public Long id() {
    return id;
  }

  public String region() {
    return region;
  }

  public String tenantId() {
    return tenantId;
  }

  public String workspaceId() {
    return workspaceId;
  }

  public String projectId() {
    return projectId;
  }

  public String jobId() {
    return jobId;
  }

  public String displayName() {
    return displayName;
  }

  public String status() {
    return status;
  }

  public String ownerUserId() {
    return ownerUserId;
  }

}
