At the moment artifacts are not used.

# Regenerating the `webauthn-assets` Artifact

## 1. Bundle the files into a tarball

```bash
cd ~/.julia/dev/WebAuthn # package root

tar czf artifacts/webauthn-assets.tar.gz \
    -C artifacts \
      index.html \
      login_success.html \
      webauthn_login.js \
      webauthn_register.js
```

## 2. Re-compute the hashes

```julia
using Tar, Inflate, SHA

tarfile   = "artifacts/webauthn-assets.tar.gz"
sha256sum = bytes2hex(open(SHA.sha256, tarfile))
gitsha    = Tar.tree_hash(IOBuffer(Inflate.inflate_gzip(tarfile)))

println("sha256: $sha256sum")
println("git-tree-sha1: $gitsha")
```

## 3. Update `Artifacts.toml`
