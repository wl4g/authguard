package com.authguard.usecases.authorization;

import com.authguard.adapter.model.AuthguardTypes.PathMap;
import com.authguard.adapter.model.AuthguardTypes.ResourceSqlMapping;
import com.authguard.adapter.model.AuthguardTypes.SegmentMap;
import java.util.List;

public final class CustomerGrowthJobResourceMappings {
  public static final String ACTION_CREATE = "customer-growth.job.create";
  public static final String ACTION_READ = "customer-growth.job.read";
  public static final String ACTION_UPDATE = "customer-growth.job.update";
  public static final String ACTION_DELETE = "customer-growth.job.delete";

  private CustomerGrowthJobResourceMappings() {}

  public static ResourceSqlMapping customerGrowthJob() {
    return new ResourceSqlMapping(
        SegmentMap.constant("prod"),
        SegmentMap.constant("customer-growth"),
        SegmentMap.column("region"),
        SegmentMap.column("tenant_id"),
        List.of(
            PathMap.literal("workspace"),
            PathMap.column("workspace_id"),
            PathMap.literal("project"),
            PathMap.column("project_id"),
            PathMap.literal("job"),
            PathMap.column("job_id")));
  }
}
