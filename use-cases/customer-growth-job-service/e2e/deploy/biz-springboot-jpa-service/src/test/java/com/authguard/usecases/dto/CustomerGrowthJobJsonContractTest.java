package com.authguard.usecases.dto;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

class CustomerGrowthJobJsonContractTest {
  private final ObjectMapper objectMapper = new ObjectMapper();

  @Test
  void createRequestReadsTheSharedSnakeCaseApiContract() throws Exception {
    CreateCustomerGrowthJobRequest request =
        objectMapper.readValue(
            """
            {
              "id": 101,
              "region": "global",
              "tenant_id": "example-corp",
              "workspace_id": "customer-insights",
              "project_id": "retention-analytics",
              "job_id": "monthly-retention-review",
              "display_name": "Monthly retention review",
              "status": "READY",
              "owner_user_id": "token-editor"
            }
            """,
            CreateCustomerGrowthJobRequest.class);

    assertThat(request.tenantId()).isEqualTo("example-corp");
    assertThat(request.workspaceId()).isEqualTo("customer-insights");
    assertThat(request.projectId()).isEqualTo("retention-analytics");
    assertThat(request.jobId()).isEqualTo("monthly-retention-review");
    assertThat(request.ownerUserId()).isEqualTo("token-editor");
  }

  @Test
  void updateRequestReadsTheSharedSnakeCaseApiContract() throws Exception {
    UpdateCustomerGrowthJobRequest request =
        objectMapper.readValue(
            """
            {
              "display_name": "Monthly retention review v2",
              "status": "PAUSED",
              "owner_user_id": "retention-operator"
            }
            """,
            UpdateCustomerGrowthJobRequest.class);

    assertThat(request.displayName()).isEqualTo("Monthly retention review v2");
    assertThat(request.status()).isEqualTo("PAUSED");
    assertThat(request.ownerUserId()).isEqualTo("retention-operator");
  }

  @Test
  void responseWritesTheSharedSnakeCaseApiContract() throws Exception {
    CustomerGrowthJobDto response =
        new CustomerGrowthJobDto(
            101L,
            "global",
            "example-corp",
            "customer-insights",
            "retention-analytics",
            "monthly-retention-review",
            "Monthly retention review",
            "READY",
            "token-editor");

    String json = objectMapper.writeValueAsString(response);

    assertThat(json)
        .contains("\"tenant_id\":\"example-corp\"")
        .contains("\"workspace_id\":\"customer-insights\"")
        .contains("\"project_id\":\"retention-analytics\"")
        .contains("\"job_id\":\"monthly-retention-review\"")
        .contains("\"owner_user_id\":\"token-editor\"")
        .doesNotContain("tenantId", "workspaceId", "projectId", "jobId", "ownerUserId");
  }
}
