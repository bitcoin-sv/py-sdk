# CHANGELOG

All notable changes to this project will be documented in this file. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Table of Contents

- [Unreleased](#unreleased)
- [1.0.4- 2025-04-28](#104---2025-04-28)
- [1.0.3 - 2025-03-26](#103---2025-03-26)
- [1.0.2 - 2025-02-28](#102---2025-02-28)
- [1.0.1 - 2025-01-09](#101---2025-01-09)
- [1.0.1 - 2025-01-09](#101---2025-01-09)
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
## [1.0.4] - 2025-04-28

### Fixed
Remove debug print statement from MerklePath.trim() method and unnecessary import statement

### Added
add step-by-step guide for sending BSV & minting NFTs

Adds a beginner-friendly tutorial that covers:
* environment setup and dependency installation
* key / address generation
* sending BSV transactions
* creating & broadcasting 1Sat Ordinals NFTs
* explanation of inputs, outputs and key terms

### Changed
Enable regular hex format broadcasting when source transactions are unavailable
Enhance the ARC broadcaster to dynamically select between EF and regular hex formats based on the availability of source transactions. This update addresses scenarios such as receiving raw hex via P2P payment destination Paymail capabilities.
Additionally, unit tests have been added to cover this feature.


---
## [1.0.3] - 2025-03-26

### Fixed
Previously, the default fee rate was hardcoded to 10 satoshis per kilobyte. This update allows users to configure the default fee rate via the TRANSACTION_FEE_RATE variable in constants.py or through the environment file.

### Added
A test for the default fee rate has also been added.

### Changed
Optimized transaction preimage calculation by refactoring the tx_preimage function to directly compute the preimage for a specified input, avoiding unnecessary computation for all inputs
Achieved a 3× performance improvement in scenarios with 250 inputs, based on benchmarking


## [1.0.2] - 2025-02-28

### Added
- BIP32_DERIVATION_PATH environment variable for customizing default derivation paths
- Dedicated BIP32 derivation functions with clearer interface
- BIP44-specific functions that build on the BIP32 foundation
- Comprehensive tests for HD wallet key derivation consistency
- Enhanced error messages for hardened key derivation attempts from xpub keys

### Fixed
- PUSHDATA opcode length parsing now uses unsigned integer reading methods (read_uint8, read_uint16_le, read_uint32_le) instead of signed integer methods to prevent incorrect chunk parsing with large data lengths
- Proper handling of edge cases in Script parsing including length 0 and incomplete length specifications
- Serialization/deserialization consistency for various PUSHDATA operations

### Changed
- Refined HD wallet key derivation interface while maintaining backward compatibility
- Improved error messages for invalid derivation attempts
- Marked legacy derivation functions as deprecated while maintaining compatibility


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

