# CHANGELOG

All notable changes to this project will be documented in this file. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Table of Contents

- [Unreleased](#unreleased)
- [1.0.0 - 2024-12-23](#100---2024-12-23)
- [0.5.2 - 2024-09-02](#052---2024-09-02)
- [0.1.0 - 2024-04-09](#010---2024-04-09)

---

## [Unreleased]

### Added
- (Include new features or significant user-visible enhancements here.)

### Changed
- (Detail modifications that are non-breaking but relevant to the end-users.)

### Deprecated
- (List features that are in the process of being phased out or replaced.)

### Removed
- (Indicate features or capabilities that were taken out of the project.)

### Fixed
- (Document bugs that were fixed since the last release.)

### Security
- (Notify of any improvements related to security vulnerabilities or potential risks.)

---
## [1.0.1] - 2025-01-09

### Added
- Enhanced WhatsOnChainBroadcaster network handling:
 - Added support for Network enum initialization (Network.MAINNET/Network.TESTNET)
 - Added robust backward compatibility for string network parameters ('main'/'test'/'mainnet'/'testnet')
 - Added input validation and clear error messages for invalid network parameters
 - Added type hints and docstrings for better code clarity
- Added comprehensive test suite for WhatsOnChainBroadcaster:
 - Added test cases for Network enum initialization
 - Added test cases for string-based network parameters
 - Added validation tests for invalid network inputs
 - Added URL construction validation tests

---


## [1.0.0] - 2024-12-23

### Added
- Fixed miner-related bugs.
- Improved documentation and updated the PyPI version.
- Implemented bug fixes and improvements based on feedback from the Yenpoint user test.

---

## [0.5.2] - 2024-09-02

### Added
- Basic functions developed by the Script team.

---

## [0.1.0] - 2024-04-09

### Added
- Initial release.

---

### Template for New Releases

Replace `X.X.X` with the new version number and `YYYY-MM-DD` with the release date:

