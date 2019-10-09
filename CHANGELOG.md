# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0-dev] - 2019-03-25
### Changed
- Post release version bump

## [0.1.2] - 2019-07-25
### Changed
- Include pkg-config dependecy on libtss2-mu in order to work with tpm2-tss 2.3
- Fix compiler error on uninitialized variable
- Fix format strings for 32bit architectures.

## [0.1.1] - 2019-04-04
### Changed
- Removed SHA384 from default PCR banks since it's unsupported by many TPMs.

## [0.1.0] - 2019-03-25
### Added
- Initial release of the an TPM2.0-based library and executable for machine to
  human authentication using the TCG's TPM Software Stack compliant tpm2-tss
  libraries.
- libtpm2totp (the library) functional implementation for reuse.
- tpm2-totp (CLI tool) executable wrapper for library.
- man-pages are included.
