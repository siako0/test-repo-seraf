resource "google_storage_bucket" "example" {
  name     = "my-example-bucket"
  location = "US"
  acl      = "private"
  versioning {
    enabled = true
  }
  uniform_bucket_level_access = true
  logging {
    log_bucket = "logs-my-example-bucket"
  }
  
  encryption {
    default_kms_key = "projects/my-project/locations/global/keyRings/my-key-ring/cryptoKeys/my-key"
  }
}