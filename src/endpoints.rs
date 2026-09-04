//! Static table of S3-compatible vendors and their endpoint patterns (spec §7).
//!
//! In-tree and static: never fetched at runtime (spec §33). Sources are the
//! vendors' own documentation, checked 2026-09-04:
//! - Wasabi: https://docs.wasabi.com/docs/what-are-the-service-urls-for-wasabi-s-different-storage-regions
//! - Cloudflare R2: https://developers.cloudflare.com/r2/api/s3/api/
//! - Backblaze B2: https://www.backblaze.com/docs/cloud-storage-s3-compatible-api
//! - DigitalOcean Spaces: https://docs.digitalocean.com/products/spaces/how-to/use-aws-sdks/
//! - Scaleway: https://www.scaleway.com/en/docs/object-storage/api-cli/using-api-call-list/
//! - Hetzner: https://docs.hetzner.com/storage/object-storage/overview
//! - Linode/Akamai: https://techdocs.akamai.com/cloud-computing/docs/access-buckets-and-files-through-urls
//! - Storj: https://storj.dev/dcs/api/s3/s3-compatibility
//! - Vultr: https://docs.vultr.com/vultr-object-storage
//! - MinIO: self-hosted; endpoint is whatever you run.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Endpoint {
    pub name: &'static str,
    pub vendor: &'static str,
    /// `{region}` is substituted; empty region means the pattern is global.
    pub pattern: &'static str,
    pub example: &'static str,
    pub regions: &'static [&'static str],
    pub notes: &'static str,
}

pub const ENDPOINTS: &[Endpoint] = &[
    Endpoint {
        name: "aws",
        vendor: "Amazon S3",
        pattern: "s3.{region}.amazonaws.com",
        example: "s3.eu-west-2.amazonaws.com",
        regions: &[
            "us-east-1",
            "us-west-2",
            "eu-west-1",
            "eu-west-2",
            "eu-central-1",
            "ap-southeast-2",
        ],
        notes: "Path-style is deprecated on AWS; Kopia uses virtual-host style automatically.",
    },
    Endpoint {
        name: "wasabi",
        vendor: "Wasabi",
        pattern: "s3.{region}.wasabisys.com",
        example: "s3.eu-west-1.wasabisys.com",
        regions: &[
            "us-east-1",
            "us-east-2",
            "us-central-1",
            "us-west-1",
            "eu-central-1",
            "eu-central-2",
            "eu-west-1",
            "eu-west-2",
            "ap-northeast-1",
            "ap-northeast-2",
            "ap-southeast-1",
            "ap-southeast-2",
            "ca-central-1",
        ],
        notes: "Region must match the bucket's region.",
    },
    Endpoint {
        name: "r2",
        vendor: "Cloudflare R2",
        pattern: "{account_id}.r2.cloudflarestorage.com",
        example: "0123456789abcdef.r2.cloudflarestorage.com",
        regions: &["auto"],
        notes: "Use --region auto. Account id comes from the Cloudflare dashboard.",
    },
    Endpoint {
        name: "b2",
        vendor: "Backblaze B2",
        pattern: "s3.{region}.backblazeb2.com",
        example: "s3.us-west-004.backblazeb2.com",
        regions: &[
            "us-west-000",
            "us-west-001",
            "us-west-002",
            "us-west-004",
            "us-east-005",
            "eu-central-003",
        ],
        notes: "Region is shown next to the bucket in the B2 console.",
    },
    Endpoint {
        name: "spaces",
        vendor: "DigitalOcean Spaces",
        pattern: "{region}.digitaloceanspaces.com",
        example: "fra1.digitaloceanspaces.com",
        regions: &[
            "nyc3", "sfo2", "sfo3", "ams3", "sgp1", "fra1", "blr1", "syd1",
        ],
        notes: "",
    },
    Endpoint {
        name: "scaleway",
        vendor: "Scaleway",
        pattern: "s3.{region}.scw.cloud",
        example: "s3.fr-par.scw.cloud",
        regions: &["fr-par", "nl-ams", "pl-waw"],
        notes: "",
    },
    Endpoint {
        name: "hetzner",
        vendor: "Hetzner Object Storage",
        pattern: "{region}.your-objectstorage.com",
        example: "fsn1.your-objectstorage.com",
        regions: &["fsn1", "nbg1", "hel1"],
        notes: "",
    },
    Endpoint {
        name: "linode",
        vendor: "Akamai (Linode) Object Storage",
        pattern: "{region}.linodeobjects.com",
        example: "eu-central-1.linodeobjects.com",
        regions: &["us-east-1", "us-southeast-1", "eu-central-1", "ap-south-1"],
        notes: "",
    },
    Endpoint {
        name: "storj",
        vendor: "Storj",
        pattern: "gateway.storjshare.io",
        example: "gateway.storjshare.io",
        regions: &["global"],
        notes: "Single global gateway.",
    },
    Endpoint {
        name: "vultr",
        vendor: "Vultr Object Storage",
        pattern: "{region}.vultrobjects.com",
        example: "ewr1.vultrobjects.com",
        regions: &["ewr1", "sjc1", "ams1", "sgp1", "blr1", "del1"],
        notes: "",
    },
    Endpoint {
        name: "minio",
        vendor: "MinIO (self-hosted)",
        pattern: "{host}:9000",
        example: "minio.example.com:9000",
        regions: &[],
        notes: "Use http:// for a local test instance; moss passes --disable-tls for http endpoints.",
    },
];

pub fn find(name: &str) -> Option<&'static Endpoint> {
    let n = name.to_ascii_lowercase();
    ENDPOINTS
        .iter()
        .find(|e| e.name == n || e.vendor.to_ascii_lowercase().contains(&n))
}

pub fn render_table(filter: Option<&str>) -> String {
    let rows: Vec<Vec<String>> = ENDPOINTS
        .iter()
        .filter(|e| filter.is_none_or(|f| find(f).is_some_and(|m| m.name == e.name)))
        .map(|e| {
            vec![
                e.name.to_string(),
                e.vendor.to_string(),
                e.pattern.to_string(),
                if e.regions.is_empty() {
                    "-".into()
                } else {
                    e.regions.join(", ")
                },
            ]
        })
        .collect();
    crate::output::human::table(&["NAME", "VENDOR", "ENDPOINT PATTERN", "REGIONS"], &rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_by_name_or_vendor() {
        assert_eq!(find("wasabi").unwrap().vendor, "Wasabi");
        assert_eq!(find("Cloudflare").unwrap().name, "r2");
        assert!(find("nope").is_none());
        assert!(render_table(Some("wasabi")).contains("wasabisys"));
        assert!(!render_table(Some("wasabi")).contains("backblaze"));
    }
}
