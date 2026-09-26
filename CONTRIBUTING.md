# Contributing to Stonechat

Every commit must carry a `Signed-off-by` line:

```
Signed-off-by: Your Name <your.email@example.com>
```

`git commit -s` adds it for you. `git rebase --signoff` fixes a branch you
already wrote.

That line is the [Developer Certificate of Origin](https://developercertificate.org/)
(DCO) 1.1, reproduced at the bottom of this file. Signing off means you have
the right to submit the code under the license that covers it. It is not a
copyright assignment — **you keep your copyright**.

Pull requests without sign-off can't be merged.

## Which license your contribution falls under

**AGPL-3.0-only**, the same as everything else here. Contributions to
`PROTOCOL.md` are CC-BY-4.0, matching the spec.

We can only accept code you're able to offer under the AGPL, so if you're
porting something in from another project, check its license first and say so
in the PR.

Sign-off is the whole requirement today. A contributor licence agreement may
be introduced later — Stonechat ships through app stores, and that eventually
needs rights the AGPL alone doesn't give us. If it happens it will be
announced here before it applies to anyone, and it will not be applied
retroactively to contributions already merged.

## Before you open a pull request

Create an issue to discuss what you want to do, even if it's a simple change. If there is no issue first, don't create a PR, it will be automatically closed. We want to avoid the infinite AI slopping.

## Developer Certificate of Origin 1.1

```
By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I have the right
    to submit it under the open source license indicated in the file; or

(b) The contribution is based upon previous work that, to the best of my
    knowledge, is covered under an appropriate open source license and I have
    the right under that license to submit that work with modifications,
    whether created in whole or in part by me, under the same open source
    license (unless I am permitted to submit under a different license), as
    indicated in the file; or

(c) The contribution was provided directly to me by some other person who
    certified (a), (b) or (c) and I have not modified it.

(d) I understand and agree that this project and the contribution are public
    and that a record of the contribution (including all personal information I
    submit with it, including my sign-off) is maintained indefinitely and may
    be redistributed consistent with this project or the open source license(s)
    involved.
```
