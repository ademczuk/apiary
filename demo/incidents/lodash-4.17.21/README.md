# lodash@4.17.21 - known-good baseline

Stub reconstruction of the canonical clean popular package. Used by the
Apiary incident replay as a control sample: the policy gate should
verdict this as **allow** when the release age is past the 14-day
minimum. The package.json carries `repository.url` and `gitHead`, has
no lifecycle scripts, and matches the shape of the real 4.17.21 release.
