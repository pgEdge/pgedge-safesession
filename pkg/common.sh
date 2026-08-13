#!/usr/bin/env bash
# common.sh - packaging environment for pgEdge SafeSession.
#
# SafeSession is a PostgreSQL extension: one build per PG major.
# pgedge-detect-build-matrix reads this to fan the matrix out over pg_versions.
PER_PG_VERSION=true

export PG_VERSION="${PG_VERSION:-17}"
export PG_MAJOR_VERSION="$(echo "$PG_VERSION" | cut -d. -f1)"

export PG_SAFESESSION_REPO="https://github.com/pgEdge/pgedge-safesession.git"
export SAFESESSION_BRANCH="${COMPONENT_BRANCH:-v1.0-alpha1}"

export SAFESESSION_VERSION="${COMPONENT_VERSION:-1.0}"
export SAFESESSION_BUILDNUM=${COMPONENT_BUILDNUM:-1}

# A retagged pre-release (v1.0-alpha1-test1) parses to a buildnum that still
# carries a dash ('alpha1-test1_1'). RPM forbids '-' in Release: and it makes
# the DEB upstream version ambiguous, so collapse it here:
# 'alpha1-test1_1' → 'alpha1test1_1'.
SAFESESSION_BUILDNUM="${SAFESESSION_BUILDNUM//-/}"

export REPO_TYPE="${REPO_TYPE:-daily}"

export SAFESESSION_DEB_VERSION="${SAFESESSION_VERSION}"
if command -v apt-get &>/dev/null; then
    if [[ "$SAFESESSION_BUILDNUM" == *_* ]]; then
        SAFESESSION_PRETAG="${SAFESESSION_BUILDNUM%%_*}"
        export SAFESESSION_DEB_VERSION="${SAFESESSION_VERSION}~${SAFESESSION_PRETAG}"
        SAFESESSION_BUILDNUM="${SAFESESSION_BUILDNUM##*_}"
    fi
fi

# release.yml stages the source tarball built from THIS run's checkout here.
export ARTIFACT_DIR="${ARTIFACT_DIR:-$(pwd)/release-artifacts}"
export SRC_TARBALL="pgedge-safesession-${SAFESESSION_VERSION}.tar.gz"

# Prefer the workflow-staged tarball (so branch / simulate_tag runs build the
# exact commit under test and need no network). The SAFESESSION_BRANCH clone is
# an opt-in fallback for local builds: set
# SAFESESSION_ALLOW_CLONE_FALLBACK=1.
stage_source() {
  local dest="$1"
  if [ -f "${ARTIFACT_DIR}/${SRC_TARBALL}" ]; then
    echo "Staging ${SRC_TARBALL} from ${ARTIFACT_DIR}"
    cp "${ARTIFACT_DIR}/${SRC_TARBALL}" "${dest}"
  elif [ -z "${SAFESESSION_ALLOW_CLONE_FALLBACK:-}" ]; then
    # A staged tarball is required by default: cloning SAFESESSION_BRANCH
    # instead would ship a package built from a different commit than
    # COMPONENT_VERSION claims.
    echo "::error::${ARTIFACT_DIR}/${SRC_TARBALL} not found. release.yml stages it with git archive; for a local build, stage it yourself or set SAFESESSION_ALLOW_CLONE_FALLBACK=1 to clone ${SAFESESSION_BRANCH} instead." >&2
    return 1
  else
    echo "Fetching SafeSession source code (${SAFESESSION_BRANCH})"
    rm -rf "pgedge-safesession-${SAFESESSION_VERSION}"
    git clone --depth=1 --branch "$SAFESESSION_BRANCH" "$PG_SAFESESSION_REPO" "pgedge-safesession-${SAFESESSION_VERSION}"
    rm -rf "pgedge-safesession-${SAFESESSION_VERSION}/.git"
    tar -czf "${SRC_TARBALL}" "pgedge-safesession-${SAFESESSION_VERSION}"
    rm -rf "pgedge-safesession-${SAFESESSION_VERSION}"
    mv "${SRC_TARBALL}" "${dest}"
  fi
}
