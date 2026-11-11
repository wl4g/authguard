from authguard_adapter.model import PathMap, ResourceSqlMapping, SegmentMap

ACTION_CREATE = "customer-growth.job.create"
ACTION_READ = "customer-growth.job.read"
ACTION_UPDATE = "customer-growth.job.update"
ACTION_DELETE = "customer-growth.job.delete"


def customer_growth_job_mapping() -> ResourceSqlMapping:
    return ResourceSqlMapping(
        SegmentMap.constant("prod"),
        SegmentMap.constant("customer-growth"),
        SegmentMap.column("region"),
        SegmentMap.column("tenant_id"),
        (
            PathMap.literal("workspace"),
            PathMap.column("workspace_id"),
            PathMap.literal("project"),
            PathMap.column("project_id"),
            PathMap.literal("job"),
            PathMap.column("job_id"),
        ),
    )
