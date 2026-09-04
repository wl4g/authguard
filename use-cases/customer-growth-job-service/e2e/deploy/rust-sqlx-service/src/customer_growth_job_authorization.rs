use authguard_adapter_rust::model::{PathMap, ResourceSqlMapping, SegmentMap};

pub const ACTION_CREATE: &str = "customer-growth.job.create";
pub const ACTION_READ: &str = "customer-growth.job.read";
pub const ACTION_UPDATE: &str = "customer-growth.job.update";
pub const ACTION_DELETE: &str = "customer-growth.job.delete";

#[must_use]
pub fn customer_growth_job_mapping() -> ResourceSqlMapping {
    ResourceSqlMapping {
        partition: SegmentMap::constant("prod"),
        service: SegmentMap::constant("customer-growth"),
        region: SegmentMap::column("region"),
        tenant: SegmentMap::column("tenant_id"),
        path: vec![
            PathMap::literal("workspace"),
            PathMap::column("workspace_id"),
            PathMap::literal("project"),
            PathMap::column("project_id"),
            PathMap::literal("job"),
            PathMap::column("job_id"),
        ],
    }
}
