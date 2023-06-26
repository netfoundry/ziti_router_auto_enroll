# Changelog

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
