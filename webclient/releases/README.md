# Web client releases

One file per build that went to https://webapp.stonechat.app, named
`<date>-<first 8 hex of the hash root>.json`: the `release.json` the build
produced, byte for byte.

The hash root is SHA-256 of the served `index.html`, which pins every
executable file by Subresource Integrity (`webclient/README` "The build
produces a hash root"). So one check tells you whether what the server is
giving you is the release recorded here:

    curl -s https://webapp.stonechat.app/ | shasum -a 256

The output must equal `hash_root` in the newest file in this directory. If
it does not, either a deploy is in progress or the origin is serving
something this repository never built — and the second is the whole point
of recording these.

`deploy.sh --webapp` (main hub deployment, private) records the file; a
self-hoster serving their own build records theirs the same way.
