# Demo app (test fixture)

A deliberately leaky Flutter app used by the integration tests: hard-coded keys via
`--dart-define`, a bundled `.env`-style file, a pinned certificate asset, a custom
MethodChannel, an exported receiver and a deep-link activity.

All secrets are fake and injected at build time by `tools/build_fixtures.sh`; this folder
contains none. Do not deploy it.
