# App Store privacy "nutrition labels"

The App Privacy questionnaire has no public API (`scripts/appstore_listing.py`
says so at the end of every run), so it is answered by hand in App Store
Connect → App → App Privacy. These are the answers, derived from what the app
actually sends off the device — the same facts as `landing/src/pages/privacy.astro`.
Change the product, change both.

Apple's test for "collected" is: transmitted off the device in a way that is
accessible to the developer or a third party. End-to-end encrypted envelopes
the relay holds are not accessible to anyone but the recipient, so message
content, media, contacts and conversation metadata are **not collected**.
Nothing is read from the address book; there is no analytics, advertising or
crash-reporting SDK (`app/pubspec.yaml`).

## Does the app collect data? — Yes

| Data type | Category | Linked to the user | Used for tracking | Purposes |
|---|---|---|---|---|
| **User ID** — the Stonechat ID (a hash of a key generated in the app) and the directory record behind it: public keys, mailbox address, token hash, creation date | Identifiers | Yes | No | App Functionality |
| **Device ID** — the APNs / FCM push token, held by the user's mailbox and the push gateway so the mailbox can wake the phone | Identifiers | Yes | No | App Functionality |

Both are required for the app to work at all, so when asked "is this data
optional for users?" the answer is no.

### Not declared, and why

- **Messages, photos, voice notes, reactions, group rosters** (User Content):
  end-to-end encrypted; the relay deletes the envelope when the phone
  acknowledges it; nobody but the recipient can read it. Not accessible → not
  collected.
- **Contacts**: never read from the address book; the app's contact list is
  user-entered Stonechat IDs and lives only on the phone.
- **Abuse reports** (User Content, user-initiated): a report carries what the
  reporter chooses to attach, including message text only if they attach it.
  This meets Apple's optional-disclosure terms — infrequent, initiated by the
  user through a clear action, not part of the app's primary function — so it
  is not declared.
- **Coarse location / country**: the user picks a mailbox country; that is a
  product choice, not device location, and the app never asks for location.
- **Diagnostics, Usage Data, Purchases, Financial Info, Browsing, Search**:
  none exist. No crash SDK, no analytics, nothing sold in this version.
- **IP address**: the servers do not log it (`--no-access-log`, and the hub
  only ever sees Caddy's address for rate limits via X-Forwarded-For). Apple
  does not list IP as a data type on its own.

## Tracking — No

No data is linked with third-party data for advertising, and nothing is
shared with data brokers. The ATT prompt is not shown and not needed.

## Privacy policy URL

`https://stonechat.app/privacy` — already set by `scripts/appstore_listing.py`
from `listing.en-US.toml`.

## What the published label will read

> **Data Linked to You** — Identifiers (User ID, Device ID), for App
> Functionality.
>
> No data used to track you.
