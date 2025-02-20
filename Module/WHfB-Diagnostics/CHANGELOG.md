# Changelog
All notable changes to the WHfB-Diagnostics module will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-02-20

### Added
- Initial module structure with basic components:
  - Module manifest (WHfB-Diagnostics.psd1)
  - Module script (WHfB-Diagnostics.psm1)
  - Public functions directory
- First public function `Get-WhfbAuthStatus`:
  - Support for checking PIN authentication status
  - Support for checking Biometric authentication status
  - Comprehensive error handling and status reporting
  - Full comment-based help with examples
  - Backward compatibility with Windows PowerShell 5.1
  - Fallback mechanisms for systems without WinBio API
- Administrative privilege requirement for secure access
- Registry-based status checking for both authentication methods
