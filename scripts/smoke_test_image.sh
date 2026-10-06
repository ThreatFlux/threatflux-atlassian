#!/usr/bin/env bash
# Smoke-test a locally available container image built from this repository.
#
#   scripts/smoke_test_image.sh cli    <image-ref> [platform]
#   scripts/smoke_test_image.sh action <image-ref> [platform]
#
# `cli` checks the Dockerfile image and `action` checks the action.Dockerfile
# image. Both must run as the distroless nonroot user (65532:65532), must ship
# no shell, and must start their binary through tini. The CLI image must also
# answer `--version` and `--help` through `app` and the `tflux-atlassian`
# symlink, pass its exec-form HEALTHCHECK command, and embed a CycloneDX SBOM.
#
# `platform` (for example linux/arm64) selects the image variant to run and is
# checked against the image's own platform; it defaults to that platform.
# Containers run with --network none: none of these checks needs the network.
set -euo pipefail

usage() {
  echo "usage: $0 cli|action <image-ref> [platform]" >&2
  exit 2
}

kind="${1:-}"
image="${2:-}"
platform="${3:-}"
[[ "${kind}" == "cli" || "${kind}" == "action" ]] || usage
[[ -n "${image}" ]] || usage

expected_user="65532:65532"

image_platform="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "${image}")"
if [[ -z "${platform}" ]]; then
  platform="${image_platform}"
elif [[ "${platform%/v[0-9]*}" != "${image_platform}" ]]; then
  echo "::error::${image} is ${image_platform}, not the requested ${platform}" >&2
  exit 1
fi
echo "Smoke-testing ${kind} image ${image} (${platform})"

run() {
  docker run --rm --network none --platform "${platform}" "$@"
}

user="$(docker image inspect --format '{{.Config.User}}' "${image}")"
if [[ "${user}" != "${expected_user}" ]]; then
  echo "::error::${image} runs as '${user}', expected ${expected_user}" >&2
  exit 1
fi
echo "ok: runs as ${user}"

# Only a missing /bin/sh may make this fail; any other failure is not evidence.
if shell_output="$(run --entrypoint /bin/sh "${image}" -c true 2>&1)"; then
  echo "::error::${image} ships /bin/sh; the runtime must stay distroless" >&2
  exit 1
fi
if ! grep -qi 'no such file' <<<"${shell_output}"; then
  echo "::error::could not determine whether ${image} ships /bin/sh: ${shell_output}" >&2
  exit 1
fi
echo "ok: no /bin/sh in the runtime image"

if [[ "${kind}" == "action" ]]; then
  # The action's ENTRYPOINT is tini followed by the action binary.
  run "${image}" --help >/dev/null
  echo "ok: tini -> threatflux-atlassian-action --help"
  exit 0
fi

# ENTRYPOINT is tini and CMD is /usr/local/bin/app, so arguments replace CMD.
echo "ok: tini -> app --version: $(run "${image}" app --version)"
run "${image}" tflux-atlassian --help >/dev/null
echo "ok: tini -> tflux-atlassian --help"
# The exec-form HEALTHCHECK command, run directly as Docker would.
run --entrypoint /usr/local/bin/app "${image}" --version >/dev/null
echo "ok: HEALTHCHECK command /usr/local/bin/app --version"

container="$(docker create --platform "${platform}" "${image}")"
trap 'docker rm -f "${container}" >/dev/null 2>&1 || true' EXIT
docker cp "${container}:/usr/share/doc/threatflux-atlassian/sbom.cdx.json" - | tar -xO | python3 -c '
import json
import sys

sbom = json.load(sys.stdin)
assert sbom.get("bomFormat") == "CycloneDX", "embedded SBOM is not CycloneDX"
components = sbom.get("components") or []
assert components, "embedded SBOM lists no components"
spec_version = sbom.get("specVersion")
print(f"ok: embedded CycloneDX {spec_version} SBOM with {len(components)} components")
'
