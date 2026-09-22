# [1.1.0](https://github.com/zlmitchell/khealth-tui/compare/v1.0.5...v1.1.0) (2026-09-22)


### Features

* etcd rescue expansion, Rancher downstream fixes, RKE2 STIG in full ([#1](https://github.com/zlmitchell/khealth-tui/issues/1)) ([3d311cf](https://github.com/zlmitchell/khealth-tui/commit/3d311cf846fc065b2b4bfb8e88175685a50b0b6d))

## [1.0.5](https://github.com/zlmitchell/khealth-tui/compare/v1.0.4...v1.0.5) (2026-09-22)


### Bug Fixes

* reach a server that changed address for the etcd rejoin ([b60c9c3](https://github.com/zlmitchell/khealth-tui/commit/b60c9c3ab46731161b0a6469b5bf1506c3138227))

## [1.0.4](https://github.com/zlmitchell/khealth-tui/compare/v1.0.3...v1.0.4) (2026-09-22)


### Bug Fixes

* etcd rejoin of a server that changed address ([155f443](https://github.com/zlmitchell/khealth-tui/commit/155f443ac3ba546be871ff7d67452d2df7cad46d))
* read the YAML shape of vsphere.conf, not only the INI one ([56165d8](https://github.com/zlmitchell/khealth-tui/commit/56165d829f52cd17af1c0b57da345b2c269466e3))

## [1.0.3](https://github.com/zlmitchell/khealth-tui/compare/v1.0.2...v1.0.3) (2026-09-22)


### Bug Fixes

* unwrap the driver union in the TridentBackend config ([97c68f7](https://github.com/zlmitchell/khealth-tui/commit/97c68f7dbd66c289df1906721e9736b6de0e65e9))

## [1.0.2](https://github.com/zlmitchell/khealth-tui/compare/v1.0.1...v1.0.2) (2026-09-22)


### Bug Fixes

* dump the ACE authn webhook file, list Rancher's delivered config-files ([5139897](https://github.com/zlmitchell/khealth-tui/commit/513989798ed69026fb304166d4039cdf6da93089))
* system namespaces per deployment, Rancher System project, Trident hints ([de4188d](https://github.com/zlmitchell/khealth-tui/commit/de4188d9aefceed189031734d581d54453878692))

## [1.0.1](https://github.com/zlmitchell/khealth-tui/compare/v1.0.0...v1.0.1) (2026-09-21)


### Bug Fixes

* rke2 bootstrap names, host keys by key, Rancher JSON files, PSA config ([673bab8](https://github.com/zlmitchell/khealth-tui/commit/673bab8d7c87757f9f1118f3ced5cbfa43643fe3))

# 1.0.0 (2026-09-21)


### Bug Fixes

* executable bit on build.sh; patch x/crypto, x/text and spdystream ([78662e8](https://github.com/zlmitchell/khealth-tui/commit/78662e80a3a65ad3e83999bd88ac78a163aa0763))


### Features

* rename to khealth-tui with a CI/release pipeline and checksummed builds ([d2253ce](https://github.com/zlmitchell/khealth-tui/commit/d2253ce1a07f9a507893bea253f176bfb1205692))
