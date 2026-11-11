package com.authguard.usecases.controller;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.authguard.usecases.dto.CustomerGrowthJobDto;
import com.authguard.usecases.dto.CustomerGrowthJobSearchRequest;
import com.authguard.usecases.dto.CreateCustomerGrowthJobRequest;
import com.authguard.usecases.service.CustomerGrowthJobService;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class CustomerGrowthJobControllerHttpContractTest {
  private CustomerGrowthJobService service;
  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    service = mock(CustomerGrowthJobService.class);
    mockMvc = MockMvcBuilders.standaloneSetup(new CustomerGrowthJobController(service)).build();
  }

  @Test
  void pathVariableBindsWithoutCompilerParameterMetadata() throws Exception {
    when(service.getJob(7L)).thenReturn(Optional.empty());

    mockMvc.perform(get("/customer-growth/jobs/7")).andExpect(status().isNotFound());

    verify(service).getJob(7L);
  }

  @Test
  void listBindsTheSharedSnakeCaseQueryContract() throws Exception {
    CustomerGrowthJobSearchRequest request =
        new CustomerGrowthJobSearchRequest(
            "customer-insights", "retention-analytics", "READY", "retention-analyst");
    when(service.listVisibleJobs(request)).thenReturn(List.of());

    mockMvc
        .perform(
            get("/customer-growth/jobs")
                .queryParam("workspace_id", request.workspaceId())
                .queryParam("project_id", request.projectId())
                .queryParam("status", request.status())
                .queryParam("owner_user_id", request.ownerUserId()))
        .andExpect(status().isOk());

    verify(service).listVisibleJobs(request);
  }

  @Test
  void createReadsAndWritesTheSharedSnakeCaseJsonContract() throws Exception {
    CreateCustomerGrowthJobRequest request =
        new CreateCustomerGrowthJobRequest(
            101L,
            "global",
            "example-corp",
            "customer-insights",
            "retention-analytics",
            "monthly-retention-review",
            "Monthly retention review",
            "READY",
            "token-editor");
    CustomerGrowthJobDto response =
        new CustomerGrowthJobDto(
            request.id(),
            request.region(),
            request.tenantId(),
            request.workspaceId(),
            request.projectId(),
            request.jobId(),
            request.displayName(),
            request.status(),
            request.ownerUserId());
    when(service.createJob(request)).thenReturn(response);

    mockMvc
        .perform(
            post("/customer-growth/jobs")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
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
                    """))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.job_id").value("monthly-retention-review"))
        .andExpect(jsonPath("$.owner_user_id").value("token-editor"));

    verify(service).createJob(request);
  }
}
