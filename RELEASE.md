# Release Process:
This document describes the general process that maintainers must follow when
making a release of the `tpm2-totp` library and cli-tool.

# Version Numbers
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

In summary: Given a version number MAJOR.MINOR.PATCH, increment the:
1. MAJOR version when you make incompatible API changes,
2. MINOR version when you add functionality in a backwards-compatible manner, and
3. PATCH version when you make backwards-compatible bug fixes.
Additional labels for pre-release and build metadata are available as extensions
to the MAJOR.MINOR.PATCH format.

## Version String
The version string is set for the rest of the autotools bits by autoconf.
Autoconf gets this string from the `AC_INIT` macro in the configure.ac file.
Once you decide on the next version number (using the scheme above) you must set
it manually in configure.ac. The version string must be in the form `A.B.C`
where `A`, `B` and `C` are integers representing the major, minor and micro
components of the version number.

## Release Candidates
In the run up to a release the maintainers may create tags to identify progress
toward the release. In these cases we will append a string to the release number
to indicate progress using the abbreviation `rc` for 'release candidate'. This
string will take the form of `_rcX`. We append an incremental digit `X` in case
more than one release candidate is necessary to communicate progress as
development moves forward.

# Git Tags
When a release is made a tag is created in the git repo identifying the release
by the [version string](#Version String). The tag should be pushed to upstream
git repo as the last step in the release process.
**NOTE** tags for release candidates will be deleted from the git repository
after a release with the corresponding version number has been made.
**NOTE** release (not release candidate) tags should be considered immutable.

## Signed tags
Git supports GPG signed tags and releases will have tags signed by a maintainer.
For details on how to sign and verify git tags see:
https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work.

# Release tarballs
We use the git tag as a way to mark the point of the release in the projects
history. We do not however encourage users to build from git unless they intend
to modify the source code and contribute to the project. For the end user we
provide release tarballs following the GNU conventions as closely as possible.

To make a release tarball use the `distcheck` make target.
This target includes a number of sanity checks that are extremely helpful.
For more information on `automake` and release tarballs see:
https://www.gnu.org/software/automake/manual/html_node/Dist.html#Dist

## Hosting Releases on Github
Github automagically generates a page in their UI that maps git tags to
'releases' (even if the tag isn't for a release). Additionally they support
hosting release tarballs through this same interface. The release tarball
created in the previous step must be posted to github using the release
interface. Additionally, this tarball must be accompanied by a detached GPG
signature. The Debian wiki has an excellent description of how to post a signed
release to Github here:
https://wiki.debian.org/Creating%20signed%20GitHub%20releases
**NOTE** release candidates must be taken down after a release with the
corresponding version number is available.

## Signing Release Tarballs
Signatures must be generated using the `--detach-sign` and `--armor` options to
the `gpg` command.

## Verifying Signatures
Verifying the signature on a release tarball requires the project maintainers
public keys be installed in the GPG keyring of the verifier. With both the
release tarball and signature file in the same directory the following command
will verify the signature:
```
$ gpg --verify tpm2-totp-X.Y.Z.tar.gz.asc
```

## Signing Keys
The GPG keys used to sign a release tag and the associated tarball must be the
same. Additionally they must:
* belong to a project maintainer
* be discoverable using a public GPG key server
* be associated with the maintainers github account
(https://help.github.com/articles/adding-a-new-gpg-key-to-your-github-account/)

# Announcements
Release candidates and proper releases should be announced on the 01.org TPM2
mailing list: https://lists.01.org/mailman/listinfo/tpm2.
This announcement should be accompanied by a link to the release page on Github
as well as a link to the CHANGELOG.md accompanying the release.
