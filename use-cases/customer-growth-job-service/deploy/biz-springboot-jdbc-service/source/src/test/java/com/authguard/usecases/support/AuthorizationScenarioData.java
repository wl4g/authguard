package com.authguard.usecases.support;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import javax.sql.DataSource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.jdbc.datasource.init.ScriptUtils;

public final class AuthorizationScenarioData {
  private static final ObjectMapper OBJECT_MAPPER =
      new ObjectMapper().setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);

  private AuthorizationScenarioData() {}

  public static AuthorizationScenarioSet authorizationScenarios() {
    try {
      var root = OBJECT_MAPPER.readTree(authguardConfigPath("e2e-scenarios.json").toFile());
      return OBJECT_MAPPER.treeToValue(root.required("authz"), AuthorizationScenarioSet.class);
    } catch (IOException error) {
      throw new IllegalStateException("Cannot load shared authorization scenarios", error);
    }
  }

  public static void seedCustomerGrowthJobs(DataSource dataSource) {
    var connection = DataSourceUtils.getConnection(dataSource);
    try {
      ScriptUtils.executeSqlScript(
          connection, new FileSystemResource(authguardConfigPath("e2e-init.sql")));
    } catch (Exception error) {
      throw new IllegalStateException("Cannot load shared customer growth job SQL", error);
    } finally {
      DataSourceUtils.releaseConnection(connection, dataSource);
    }
  }

  private static Path authguardConfigPath(String name) {
    String relative = name.equals("e2e-init.sql")
        ? "deploy/postgresql/source/init.sql" : "deploy/authguard/source/scenarios.json";
    Path current = Path.of("").toAbsolutePath().normalize();
    while (current != null) {
      Path local = current.resolve(relative);
      if (Files.isRegularFile(local)
          && current.getFileName() != null
          && current.getFileName().toString().equals("customer-growth-job-service")) {
        return local;
      }
      Path repositoryRelative =
          current.resolve("use-cases/customer-growth-job-service").resolve(relative);
      if (Files.isRegularFile(repositoryRelative)) {
        return repositoryRelative;
      }
      current = current.getParent();
    }
    throw new IllegalStateException("Cannot locate use-case config file: " + name);
  }

  public record AuthorizationScenarioSet(int accessContextVersion, List<AuthorizationScenario> scenarios) {}

  public record AuthorizationScenario(
      String id,
      String operation,
      String principalId,
      String action,
      String resourceUrn,
      List<String> allowResourceUrns,
      List<String> denyResourceUrns,
      ScenarioCriteria criteria,
      Long targetJobId,
      ScenarioJob job,
      ScenarioUpdate update,
      Map<String, Object> conditions,
      Map<String, Object> evaluationContext,
      boolean gatewayAllowed,
      boolean expectedAllowed,
      List<Long> expectedJobIds,
      String expectedStatus) {}

  public record ScenarioCriteria(
      String workspaceId, String projectId, String status, String ownerUserId) {}

  public record ScenarioJob(
      Long id,
      String region,
      String tenantId,
      String workspaceId,
      String projectId,
      String jobId,
      String displayName,
      String status,
      String ownerUserId) {}

  public record ScenarioUpdate(String displayName, String status, String ownerUserId) {}
}
