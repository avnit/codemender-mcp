# Network for the codemender-sandbox Cloud Run Job.
#
# The sandbox has no internet egress. The only allowed egress is HTTPS to the
# restricted.googleapis.com VIP (199.36.153.4/30), reached through Private
# Google Access. Source tarballs and patches are staged in GCS; the sandbox
# cannot clone from GitHub.
#
# There is intentionally NO Cloud Router / Cloud NAT. Adding one would give
# the sandbox a path to the internet and break the isolation model.

resource "google_compute_network" "sandbox_vpc" {
  project                 = var.project_id
  name                    = "sandbox-vpc"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"

  depends_on = [google_project_service.apis]
}

resource "google_compute_subnetwork" "sandbox_subnet" {
  project                  = var.project_id
  name                     = "sandbox-subnet"
  region                   = var.region
  network                  = google_compute_network.sandbox_vpc.id
  ip_cidr_range            = "10.10.0.0/24"
  private_ip_google_access = true
}

resource "google_compute_firewall" "sandbox_deny_all_egress" {
  project            = var.project_id
  name               = "sandbox-deny-all-egress"
  network            = google_compute_network.sandbox_vpc.name
  direction          = "EGRESS"
  priority           = 65000
  destination_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "all"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "sandbox_allow_restricted_apis" {
  project            = var.project_id
  name               = "sandbox-allow-restricted-apis"
  network            = google_compute_network.sandbox_vpc.name
  direction          = "EGRESS"
  priority           = 1000
  destination_ranges = ["199.36.153.4/30"]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

# Private DNS: resolve *.googleapis.com to restricted.googleapis.com inside
# sandbox-vpc so GCS calls go to the restricted VIP.
resource "google_dns_managed_zone" "googleapis_restricted" {
  project     = var.project_id
  name        = "sandbox-googleapis-restricted"
  dns_name    = "googleapis.com."
  description = "Maps googleapis.com to the restricted VIP for sandbox-vpc."
  visibility  = "private"

  private_visibility_config {
    networks {
      network_url = google_compute_network.sandbox_vpc.id
    }
  }
}

resource "google_dns_record_set" "googleapis_wildcard_cname" {
  project      = var.project_id
  managed_zone = google_dns_managed_zone.googleapis_restricted.name
  name         = "*.googleapis.com."
  type         = "CNAME"
  ttl          = 300
  rrdatas      = ["restricted.googleapis.com."]
}

resource "google_dns_record_set" "restricted_googleapis_a" {
  project      = var.project_id
  managed_zone = google_dns_managed_zone.googleapis_restricted.name
  name         = "restricted.googleapis.com."
  type         = "A"
  ttl          = 300
  rrdatas      = ["199.36.153.4", "199.36.153.5", "199.36.153.6", "199.36.153.7"]
}
