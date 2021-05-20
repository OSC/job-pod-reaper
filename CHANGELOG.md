## Unreleased

* Support reaping orphaned objects if object's corresponding pod job is gone
* **BREAKING** Rename --pods-labels flag to --object-labels, rename Helm value podsLabels to objectLabels

## v0.4.0 / 2021-04-14

* Update Kubernetes Go dependencies to 0.20.5 (Kubernetes 1.20.x)
* Upgrade to Go 1.16

## v0.3.0 / 2021-02-16

* Make job label optional
* Simplify how versions are set for Helm chart (version naming changed)

## v0.2.1 / 2021-02-08

* Fix Helm chart tag version

## v0.2.0 / 2021-02-08

* Add support for installing with Helm

## v0.1.0 / 2021-01-13

* Initial release
