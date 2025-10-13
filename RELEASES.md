# Releases

## How this crate is released

For now, `axum-jose` is released manually. The release process is as follows:

1. Checkout the `main` branch and run `release-plz update` to update the crate version and changelog following semver principles.
2. Add a release tag to, e.g. `git tag v<version>` and push the tag to GitHub.
3. Generate a personal access token (PAT) in GitHub. Specifically, generate a "Fine-grained token" scoped to the
   `axum-jose` repository with **Read-only** permission on repository "Metadata" and **Read and write** permission for
   repository "Contents".
4. Generate an [API token on for crates.io](https://crates.io/settings/tokens) with the **publish-update** scope.
5. Finally, to publish the release run `release-plz release --git-token=<github-token> --token=<crates.io-token>` with
   the above generated tokens. It may take a while for the command to complete but once it does, the release should be
   available on both GitHub and crates.io.
