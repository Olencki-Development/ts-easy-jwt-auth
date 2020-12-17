# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2020-12-17
### Added
* StatusCode to errors
* Check for register to see if user already exists
* Easier way import custom errors
* Support for passing entire header into validate

### Changed
* Have InvalidRoleError extend ForbiddenError to return same information
* Login method returns the user
* Time expiration to number in seconds vs string
* Validate method returns tokens and user

## [1.0.0] - 2020-12-14
### Added
* EasyJWTAuth class
* EasyJWTAuth types
* IEasyJWTAuth interface
* Javascript example
* Typescript example
