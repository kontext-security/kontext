# Browser event contract v1

The messages between the Kontext browser extension, `kontext browser-host` and
the daemon, and the batch the daemon sends to the cloud. The extension lives in
a separate repository and vendors this folder at a pinned commit; this folder
is the source of truth.

The extension records which AI web apps are used. It never sends what people
write, URL paths, query strings or tokens: hostnames only.

## Extension to daemon

Native messaging carries one JSON message per frame. `kontext browser-host`
checks the caller, then relays each message to the daemon unchanged and writes
the daemon's answer back.

- `hello`: sent once per connection. Carries the extension's version, browser
  and profile id (a random id the extension makes; never the profile's email).
- `records`: up to 200 records, and `enrollment`: the enrollment id from the
  settings answer the records were made under. The daemon refuses every
  record of a message made for another enrollment than its own, and its answer
  names the enrollment it checked them against.

Record kinds in v1:

| Kind | Meaning |
|---|---|
| `health` | The extension is running: when it connected and when it was last seen. |
| `visit` | An AI web app from the catalog was used that UTC day: first and last time, and `requests`, the number of page loads plus POST requests to the app's hosts. Page loads alone would miss a tab kept open for days; every request would count an idle tab that polls. `messages` is how many of those requests were sends to the app's message endpoint: messages sent, approximate, as a regenerate or an edit is a send too. It is a count for the day, never an event per message, and never more than `requests`. A send is a POST to one of the app's `sends` paths in the catalog (`*` is one path segment, such as an id); the extension compares the path and drops it. |
| `account` | Which kind of account was signed in to an app that UTC day, at the newest observation: `plan` is `anonymous` (not signed in), `free` or `paid` (a personal account), `team` or `enterprise` (an organisation's workspace), or `unknown` (the app's answer could not be read). `corporate` is true for a team or enterprise workspace, or for an account whose email domain is one of `corporate_domains`. |

`day` is the UTC date. A `visit` is a snapshot of the day so far with an
absolute count, never an increment, so sending it twice is harmless.

An `account` never carries an address or a name. `email_domain` is sent only
for a corporate account; a personal account's domain stays in the browser.
The daemon keeps the newest `account` of each app and day per profile, and
refuses one recorded for another enrollment, as it does visits. An account's
`app` and `host` are held to the catalog as a visit's are.

The catalog is [`catalog.json`](catalog.json), part of this contract: the
extension is built from it and the daemon checks visits against it. A visit's
`app` must be a catalog id, `app_name` and `provider` must be that entry's own
`name` and `provider`, and `host` one of its `hosts` (`*.example.com` matches
any name below example.com). So no field of a visit can carry a page title, a
URL or other text people or pages wrote. The schema holds names to the
catalog's shape (at most 40 letters, digits, spaces and `. & + ' ( ) -`); a
catalog entry must fit it too. `extension.version` is at most 32 characters.

## Daemon to extension

Every message gets a `settings` answer: the Data collection step
(`commands`, `full` or `prompts`, as the dashboard names them), the
organisation's corporate email domains, `paused`, which records were
accepted, and `enrollment`: an opaque id of the enrollment the daemon records
under, empty until it has one. When `enrollment` changes, the extension drops
the visits it kept for the previous one, so nothing recorded for one workspace
reaches another; the daemon drops its own rows on the same change. While
`enrollment` is empty the extension sends only `hello`. While `paused` is true
the extension stops every detector and sends
only `hello` and `health`. In v1 the daemon always answers `paused: false`,
until it gets a server source with the endpoint configuration. Its corporate
domains are the domain of the enrolled user's email, unless that is a consumer
webmail domain, until the dashboard has a list of its own.

A message with another contract version gets an `error` answer with
`unsupported_contract`. The extension then stops recording until a handshake
in its own version succeeds.

## Daemon to cloud

`POST /api/v1/browser-activity/batches` with the install token, body
`browser-activity-v1`. Each record carries the browser, profile and extension
version it came from. The answer accepts records one by one: a rejected record
is listed with its index and reason and is dropped, not retried.

## Who may connect

`kontext browser-host` accepts only the extension IDs compiled into it. A
release build lists the store IDs and nothing else, so until they exist it
refuses every caller. Only a build with the `kontext_browser_dev` tag also
accepts the dev ID that the extension's dev builds carry.

## Rules for both sides

- Read `contract` first. A message of another version gets
  `unsupported_contract` whatever the rest looks like; a message without one is
  invalid.
- Keys match exactly: `Type` is an unknown field, not `type`.
- Unknown fields are ignored, whatever their type, and so are fields that
  belong to the other record kind. An unknown record kind is rejected.
- A visit's `first_seen` and `last_seen` fall on its `day` in UTC, in order.
- Empty lists are `[]`, never `null`.
- The cloud batch is stricter than an extension's message: a record there
  carries only its own kind's fields.
- The cloud's answer accounts for every record of the batch once: `accepted`
  plus the distinct indexes in `rejected`, each with a `reason`. It carries no
  `type`, `schema` or `contract`. Any other answer is an error and the batch is
  sent again. The daemon does not follow redirects.
- `fixtures/valid` must decode on both sides; `fixtures/invalid` must be
  rejected. `schema.json` describes the same shapes.
