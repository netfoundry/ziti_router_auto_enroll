# Changelog

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
## [1.0.19] - 2023-12-28

### Added

- Add skipDNS to not configure local DNS
- Add skipSystemd to not configure systemd nor take any systemd actions

## [1.0.18] - 2023-12-13

### Changed

- Default to not including metrics unless specified.
- Changed the default reportInterval to 60s

## [1.0.17] - 2023-11-27

### Changed

- Changed default version endpoint to use client endpoint


## [1.0.16] - 2023-11-09

### Added

- Added explicit permissions to directory creation

## [1.0.15] - 2023-11-02

### Added

- Added cleanup of previous binaries to fix re-enrollment issues to higher network versions.

## [1.0.14] - 2023-09-28

### Added

- Add support for proxy configuration

## [1.0.13] - 2023-08-29

### Fixed

- Fix issue with os version comparison when handling DNS
## [1.0.12] - 2023-08-21

### Added

- Add support to update resolved configuration for Debian12

## [1.0.11] - 2023-08-02

### Changed

- Fixed issue where local default ip isn't returned after networkd is restarted

## [1.0.10] - 2023-07-27

### Changed

 - Fixed issue where specified linkListener advertise value was not included in the crs sans

## [1.0.9] - 2023-07-17

### Changed

- Add dnsSvcIpRange to tunnelListener proxy config
- Add linkCheck healthcheck to default config

## [1.0.8] - 2023-07-17

### Changed

- Handle 0.29.0 bundle directory structure.
- Enforce the mode to be execuable while extracting files from the bundle.

## [1.0.7] - 2023-06-23

### Changed

- Added iptables flush back into systemd unit file.

## [1.0.6] - 2023-06-20

### Changed

- Removed ebpf pre exec steps from the systemd unit file.

## [1.0.5] - 2023-06-13

### Changed

- Moved the function handle_dns to after the install of binaries & enrollment.
- Moved root check to before setting log file.

## [1.0.4] - 2023-05-32

### Fixed

- Fixed issue with not passing in all options for link listeners.

### Added

- Additional debug statements in controller connection.

## [1.0.3] - 2023-05-16

### Changed

- Changed default install directory to /opt/openziti/ziti-router

## [1.0.2] - 2023-04-28

### Fixed 

- Don't attempt to stop the current ziti-router if just printing a config, combo of (-f & -p) was 
  causing this to happen.

## [1.0.1] - 2023-04-28

### Fixed 

- Fixed issue when iptables is not installed starting the router would fail.
  Add logic so it will not allow you to continue install unless iptables
  is installed if choosing tunneler with tproxy mode. 

## [1.0.0] - 2023-04-27

- Initial version
