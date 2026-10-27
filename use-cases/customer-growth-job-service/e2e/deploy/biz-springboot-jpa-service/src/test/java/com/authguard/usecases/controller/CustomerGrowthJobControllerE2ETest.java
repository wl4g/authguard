package com.authguard.usecases.controller;

import static org.assertj.core.api.Assertions.assertThat;

import com.authguard.adapter.access.AuthguardAccess;
import com.authguard.adapter.filter.AuthguardAccessInterceptor;
import com.authguard.adapter.model.AuthguardTypes.AccessContext;
import com.authguard.adapter.util.AuthguardUtils;
import com.authguard.usecases.dto.CustomerGrowthJobDto;
import com.authguard.usecases.dto.CreateCustomerGrowthJobRequest;
import com.authguard.usecases.dto.UpdateCustomerGrowthJobRequest;
import com.authguard.usecases.repository.CustomerGrowthJobJpaRepository;
import com.authguard.usecases.service.CustomerGrowthJobService;
import com.authguard.usecases.support.E2EFixtures;
import com.authguard.usecases.support.E2EFixtures.AuthorizationScenario;
import com.authguard.usecases.support.E2EFixtures.ScenarioCriteria;
import jakarta.persistence.EntityManager;
import java.util.List;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

@DataJpaTest
@Import({CustomerGrowthJobJpaRepository.class, CustomerGrowthJobService.class, CustomerGrowthJobController.class})
class CustomerGrowthJobControllerE2ETest {
  private static final String TEST_SIGNING_KEY =
      "test-access-context-hmac-key-32-bytes-minimum";
  @Autowired private DataSource dataSource;

  @Autowired private EntityManager entityManager;

  @Autowired private CustomerGrowthJobController controller;

  @Test
  void authorizationScenariosFromSharedFixture() {
    E2EFixtures.AuthorizationFixture fixture = E2EFixtures.authorizationScenarios();
    assertThat(fixture.scenarios()).hasSizeGreaterThanOrEqualTo(30);

    for (AuthorizationScenario scenario : fixture.scenarios()) {
      seedCustomerGrowthJobs();
      RequestAccessScope accessScope = enterContext(fixture.accessContextVersion(), scenario);
      try {
        ScenarioResult result = executeScenario(scenario);
        assertThat(result.allowed())
            .as("scenario %s", scenario.id())
            .isEqualTo(scenario.expectedAllowed());
        if (!scenario.expectedAllowed()) {
          assertDeniedMutationDidNotChangeDatabase(scenario);
        }
        if (scenario.operation().equals("list") && scenario.expectedAllowed()) {
          assertThat(result.jobIds())
              .as("scenario %s", scenario.id())
              .containsExactlyElementsOf(scenario.expectedJobIds());
        }
        if (scenario.expectedStatus() != null && !scenario.expectedStatus().isBlank()) {
          assertThat(result.status())
              .as("scenario %s", scenario.id())
              .isEqualTo(scenario.expectedStatus());
        }
      } finally {
        accessScope.close();
      }
      System.out.printf("AUTHGUARD_E2E_CASE id=%s%n", scenario.id());
    }
  }

  private ScenarioResult executeScenario(AuthorizationScenario scenario) {
    try {
      return switch (scenario.operation()) {
        case "list" -> {
          ScenarioCriteria criteria =
              scenario.criteria() == null
                  ? new ScenarioCriteria(null, null, null, null)
                  : scenario.criteria();
          List<CustomerGrowthJobDto> jobs =
              controller.listVisibleJobs(
                  criteria.workspaceId(),
                  criteria.projectId(),
                  criteria.status(),
                  criteria.ownerUserId());
          yield new ScenarioResult(true, jobs.stream().map(CustomerGrowthJobDto::id).toList(), null);
        }
        case "get" ->
            new ScenarioResult(
                controller.getJob(scenario.targetJobId()).getStatusCode() == HttpStatus.OK,
                List.of(),
                null);
        case "create" -> {
          var job = scenario.job();
          CustomerGrowthJobDto created =
              controller.createJob(
                  new CreateCustomerGrowthJobRequest(
                      job.id(),
                      job.region(),
                      job.tenantId(),
                      job.workspaceId(),
                      job.projectId(),
                      job.jobId(),
                      job.displayName(),
                      job.status(),
                      job.ownerUserId()));
          yield new ScenarioResult(created.id().equals(job.id()), List.of(), created.status());
        }
        case "update" -> {
          var update = scenario.update();
          CustomerGrowthJobDto updated =
              controller.updateJob(
                  scenario.targetJobId(),
                  new UpdateCustomerGrowthJobRequest(
                      update.displayName(), update.status(), update.ownerUserId()));
          yield new ScenarioResult(true, List.of(), updated.status());
        }
        case "delete" -> {
          controller.deleteJob(scenario.targetJobId());
          Number remaining =
              (Number)
                  entityManager
                      .createNativeQuery("SELECT COUNT(*) FROM e2e_authguard_customer_growth_jobs WHERE id = ?")
                      .setParameter(1, scenario.targetJobId())
                      .getSingleResult();
          yield new ScenarioResult(remaining.longValue() == 0, List.of(), null);
        }
        default -> throw new IllegalArgumentException("Unsupported operation: " + scenario.operation());
      };
    } catch (RuntimeException error) {
      entityManager.clear();
      return new ScenarioResult(false, List.of(), null);
    }
  }

  private void assertDeniedMutationDidNotChangeDatabase(AuthorizationScenario scenario) {
    switch (scenario.operation()) {
      case "create" ->
          assertThat(countById(scenario.job().id())).isZero();
      case "update" ->
          assertThat(
                  entityManager
                      .createNativeQuery("SELECT status FROM e2e_authguard_customer_growth_jobs WHERE id = ?")
                      .setParameter(1, scenario.targetJobId())
                      .getSingleResult())
              .isEqualTo("READY");
      case "delete" ->
          assertThat(countById(scenario.targetJobId())).isOne();
      default -> {
        // Read-only operations cannot mutate the fixture.
      }
    }
  }

  private long countById(Long id) {
    return ((Number)
            entityManager
                .createNativeQuery("SELECT COUNT(*) FROM e2e_authguard_customer_growth_jobs WHERE id = ?")
                .setParameter(1, id)
                .getSingleResult())
        .longValue();
  }

  private static RequestAccessScope enterContext(int version, AuthorizationScenario scenario) {
    AuthguardAccessInterceptor interceptor =
        new AuthguardAccessInterceptor(
            new AuthguardAccess.HeaderAccessContextResolver(TEST_SIGNING_KEY));
    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();
    Object handler = new Object();
    if (scenario.gatewayAllowed()) {
      request.addHeader(
          AuthguardUtils.ACCESS_CONTEXT_HEADER,
          AuthguardUtils.signAccessContext(
              AccessContext.active(
                  scenario.principalId(),
                  scenario.action(),
                  scenario.resourceUrn(),
                  scenario.allowResourceUrns(),
                  scenario.denyResourceUrns()),
              TEST_SIGNING_KEY));
      assertThat(version).isEqualTo(3);
    }
    assertThat(interceptor.preHandle(request, response, handler))
        .as("gateway access for scenario %s", scenario.id())
        .isEqualTo(scenario.gatewayAllowed());
    return new RequestAccessScope(interceptor, request, response, handler);
  }

  private void seedCustomerGrowthJobs() {
    E2EFixtures.seedCustomerGrowthJobs(dataSource);
    entityManager.clear();
  }

  private record ScenarioResult(boolean allowed, List<Long> jobIds, String status) {}

  private record RequestAccessScope(
      AuthguardAccessInterceptor interceptor,
      MockHttpServletRequest request,
      MockHttpServletResponse response,
      Object handler) {
    void close() {
      interceptor.afterCompletion(request, response, handler, null);
    }
  }
}
