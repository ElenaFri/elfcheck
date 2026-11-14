# Publishing elfcheck on the openSUSE Build Service (OBS)

OBS builds elfcheck **from source** in a clean chroot and publishes a **signed**
RPM repository, so end users install it with a plain `zypper install elfcheck`
(no `--no-gpg-checks`, no manual key import) and get automatic updates. This is
the frictionless path that a standalone `.rpm` file cannot offer, because a
downloaded file's signing key is never pre-trusted on the user's system.

This directory holds everything OBS needs:

- `elfcheck.spec` — a from-source spec (`BuildRequires: nasm binutils make`;
  `%build` runs `make`, `%install` runs `make install`, `%check` validates the
  built binary). It is distinct from `../elfcheck.spec`, which packages a
  **prebuilt** binary for GitHub release assets.
- `_service` — an OBS source service that checks out this git repository at a
  release tag, builds a versioned tarball, and rewrites `Version:` in the spec
  to match the tag (so the package version stays tied to the release tag, which
  mirrors `version_msg` in `src/elfcheck_data.inc`).

## One-time setup

1. Create a free account on <https://build.opensuse.org>.
2. Install and configure the CLI:

   ```bash
   sudo zypper install osc
   osc login        # stores credentials in ~/.config/osc/oscrc
   ```

3. Create a package in your home project (replace `home:ElenaFri` if you use a
   different project name — and update the `url` in `_service` if you fork):

   ```bash
   osc checkout home:ElenaFri
   cd home:ElenaFri
   osc mkpac elfcheck
   cp /path/to/elfcheck/packaging/obs/_service        elfcheck/
   cp /path/to/elfcheck/packaging/obs/elfcheck.spec   elfcheck/
   cd elfcheck
   osc add _service elfcheck.spec
   ```

4. Enable build targets (architectures and distributions) for the project in the
   web UI — add **x86_64** for e.g. `openSUSE_Tumbleweed`, `openSUSE_Leap_15.6`
   and `Fedora_*`. The spec is `ExclusiveArch: x86_64`, so other arches are
   skipped automatically.

## Each release

Bump `<revision>` in `_service` to the new tag (e.g. `v1.2.0`) and commit:

```bash
osc service runall          # fetch the tarball + sync Version locally (optional)
osc commit -m "elfcheck 1.2.0"
```

OBS rebuilds from source and re-signs the repository automatically. (OBS manages
the repository signing key itself; the GitHub-release `GPG_PRIVATE_KEY` secret is
only for the standalone `.rpm` artifacts and is unrelated to OBS.)

## What end users then run

Once the project publishes (see the "Download" page on
`software.opensuse.org/package/elfcheck` or your project's repository page):

```bash
# openSUSE Tumbleweed (adjust the distro path for Leap/Fedora)
sudo zypper addrepo --refresh \
  https://download.opensuse.org/repositories/home:/ElenaFri/openSUSE_Tumbleweed/home:ElenaFri.repo
sudo zypper --gpg-auto-import-keys refresh
sudo zypper install elfcheck
```

After the one-time `addrepo`, the signing key is trusted and future
`zypper install` / updates need no extra flags.
