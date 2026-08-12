#!/bin/bash
set -euo pipefail

RHEL="$(rpm --eval %rhel)"

prepare() {
  setup_dnf_build_env
  echo "Copying packaging files..."
  cp "${COMPONENT_DIR}/rpm/pgedge-safesession.spec" ~/rpmbuild/SPECS/

  # The spec's Source0 basename is v<version>.tar.gz (a GitHub tag archive),
  # while %setup expects the pgedge-safesession-<version>/ directory inside it
  # — which is what release.yml's `git archive --prefix` produces.
  stage_source ~/rpmbuild/SOURCES/v${SAFESESSION_VERSION}.tar.gz

  # This function is for debugging purpose if you have your own keys. GH workflow sets it
  #import_gpg_keys

  echo "🔧 Installing RPM build dependencies..."
  dnf builddep -y \
    --define "safesession_version ${SAFESESSION_VERSION}" \
    --define "safesession_buildnum ${SAFESESSION_BUILDNUM}" \
    --define "pgmajorversion ${PG_MAJOR_VERSION}" \
    ~/rpmbuild/SPECS/pgedge-safesession.spec
}

build() {
  QA_RPATHS=$(( 0xffff )) rpmbuild -ba ~/rpmbuild/SPECS/pgedge-safesession.spec \
    --define "safesession_version ${SAFESESSION_VERSION}" \
    --define "safesession_buildnum ${SAFESESSION_BUILDNUM}" \
    --define "pgmajorversion ${PG_MAJOR_VERSION}"
}

post_build() {
  echo "📤 Copying built RPMs to /output..."
  mkdir -p /output
  cp -v ~/rpmbuild/RPMS/*/*.rpm /output/ || echo "No binary RPMs found"
  cp -v ~/rpmbuild/SRPMS/*.src.rpm /output/ || echo "No SRPM found"

  sign_rpms /output/*.rpm
  validate_signatures /output/*.rpm
}
