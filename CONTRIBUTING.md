# Guidelines for submitting bugs:
All non security bugs should be filed on the Issues tracker:
https://github.com/tpm2-software/tpm2-totp/issues

Security sensitive bugs should be emailed to a maintainers directly.

# Guideline for submitting changes:
All changes to the source code must follow the coding standard used in the
tpm2-tss project [here](https://github.com/tpm2-software/tpm2-tss/blob/master/doc/coding_standard_c.md).

All changes should be introduced via github pull requests. This allows anyone to
comment and provide feedback in lieu of having a mailing list. For pull requests
opened by non-maintainers, any maintainer may review and merge that pull
request. For maintainers, they either must have their pull request reviewed by
another maintainer if possible, or leave the PR open for at least 24 hours, we
consider this the window for comments.

## Patch requirements
* All tests must pass on Travis CI for the merge to occur.
* All changes must not introduce superfluous changes or whitespace errors.
* All commits should adhere to the git commit message guidelines described
here: https://chris.beams.io/posts/git-commit/ with the following exceptions.
 * We allow commit subject lines up to 80 characters.
* All contributions must adhere to the Developers Certificate of Origin. The
full text of the DCO is here: https://developercertificate.org/. Contributors
must add a 'Signed-off-by' line to their commits. This indicates the
submitters acceptance of the DCO.

## Guideline for merging changes

Pull Requests MUST be assigned to an upcoming release tag. If a release milestone does
not exist, the maintainer SHALL create it per the [RELEASE.md](RELEASE.md) instructions.
When accepting and merging a change, the maintainer MUST edit the description field for
the release milestone to add the CHANGELOG entry.

Changes must be merged with the "rebase" option on github to avoid merge commits.
This provides for a clear linear history.
