# The ACME test server, re-tagged into a single-platform image.
#
# It is not modified: this exists because the published image is a manifest
# list with attestations attached, and the cluster's image loader takes an
# image for one platform. Building on top of it produces exactly that, and
# gives the tests one place to pin the version from.
FROM ghcr.io/letsencrypt/pebble:latest@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199
