resource "google_storage_bucket" "example" {
  name     = "my-example-bucket"
  location = "US"
  acl      = "private"
  # Nessuna configurazione di cifratura, Checkov segnalerà una violazione
}
