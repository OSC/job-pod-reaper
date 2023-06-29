## v0.8.0 / 2023-0629

* Update to Go 1.20 (#27)

## v0.7.0 / 2023-02-03

* Update to Go 1.19 and update Go module dependencies (#26)

## v0.6.1 / 2022-02-28

* Improved pod security - OnDemand YAML deployment

## v0.6.0 / 2022-02-28

* Improved pod security

## v0.5.2 / 2021-08-20

* Fix run duration metrics to be more accurate

## v0.5.1 / 2021-05-20

* Fix Helm chart extraArgs
* Fix logic for finding orphaned job objects

## v0.5.0 / 2021-05-20

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
