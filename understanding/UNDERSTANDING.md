# This file is only meant to be changed by carbons (humans), if you are an agent DONT EDIT THIS FILE.  


# UNDERSTANIDNG.md - HOOK

This understanding contains everything about how silicon hook would work, and what all is expected from the system. 

So silicon hook is our internal service to receive, verify and store webhooks from various apps. Ting will only be used as our internal delivery layer to send these events to silicons and carbons. The user never needs to know about Hook or Ting, the app using them handles the setup and authorization internally.

# Glossary

`Carbon` - The human in the system. Every human account is called a carbon.
`Silicon` - Our AI Agent (silicon) account is refered to as a Silicon.
`Org` - This is our organisation, this is where all the silicons and carbons would stay for a single organisation and defines the scope. 


# Login

Logging in and signing up are handled entirely by Silicon IAm (this is our access and authorization management layer). You would have an app_id and app_secret stored in your env that you can use to request the login and signup from Silicon IAm (read [(https://github.com/teamofsilicons/silicon-iam/tree/main/docs/client)]) you would realise how you would need to login and singup using silicon IAm. For both signing in and signing up into the system would need Silicon IAm authorization, once you have the access token from SIlicon IAm for the user logged in, render the application accordingly. 

Use the oficial and latest silicon client for using IAm at all times and across everywhere. (https://crates.io/crates/silicon-iam-client/)

The webhook endpoint ([backend.hook.teamofsilicons.com/webhook/]) you have would give you information whenever someone logs out, kicked from org, anything changes you would know.

Mainly this will be used by authenticated silicons, so take a look at how silicon's are authenticated and let the silicons do the action accordingly. 

Webhooks are just for silicons to use, and when carbons come into the system for the other silicons that they have authority to view they should be able to open that silicon and see all the active webh ook connections and the logs and the history, etc for that silicon and the specific webhooks. 


# How it works

For any silicon that authenticates onto silicon hook, see if they have a valid silicon account, and if they have a valid silicon account. This is the base id that's gonna be used by the silicon for all the webhook endpoints.

There should be an endpoint to get all the hooks, it should return the name of the hook, the hook url, and when it last reached out.

For every single hook event sent through Ting, the hook event should be in the format:
```
"type": "new_event",
"data": {
	"sender": "stripe",
	"metadata": {
		metadata here
	}
}
```

Just these 2 feilds must be present in the hook event. And metadata included inside data itself. Ting wraps this in its own delivery format internally.


# Rotate

There should be an endpoint to rotate, which kills the earlier hook url for that particular service instead replaces it with a new endpoint (a new 8 digit alphanumerical that's not already registered for that silicon id) and return it in the same endpoint. The killed endpoint should never be used for the same silicon again 


# Url

Each web hook endpoint would be at [hook.teamofsilicons.com/silicon/{silicon_id}/{8_digit_alphanumerical}]

For eg:
hook.teamofsilicons.com/silicon/si:cos/402E2J2U

The entire 8_digit_alphanumerical must be in all caps. 

# Create Webhook

A silicon or carbon should be able to create an webhook, for creating an webhook it requires the Name of the service that the webhook is for, and an optional description, i should also be able to set that do we need signature for this one or not (by default it's enabled, but can be disabled) define the signing_secret_algorithm at this step, these are all the possible blocks that could combine:

```
request
	raw_body
	raw_body_bytes
	body
		`- any JSON path`
		
	form
		`- any key`

	multipart
		`- any key`

	method

	url
	scheme
	authority
	host
	hostname
	port
	path

	query_string
	query
		`- any key`

	headers
		`- ANY HEADER`

	cookies
		`- any key`

hook
	id
	url

secret
key
	public

```

any of the following blocks can be used, for any kye or any header, it should be configurable like `headers.timestamp`, etc. For each one of the blocks these operations can be performed on them:

```
concat(...values), join(separator: "" | "." | ":" | "," | ";" | "\n" | " ", ...values), sort(values, order: asc | desc), sort_keys(object, order: asc | desc), utf8(value), ascii(value), url_encode(value), url_decode(value), percent_encode(value), percent_decode(value), canonicalize_url(url), canonicalize_query(query), json_encode(value), form_encode(value), sha1(value), sha256(value), sha384(value), sha512(value), hex(value), hex_decode(value), base64(value), base64_decode(value), base64url(value), base64url_decode(value), lowercase(value), uppercase(value), trim(value); signature_algorithm: HMAC-SHA1 | HMAC-SHA256 | HMAC-SHA384 | HMAC-SHA512 | SHA1 | SHA256 | SHA384 | SHA512 | Ed25519 | ECDSA-SHA256 | RSA-SHA1 | RSA-SHA256;`

signature_encoding: hex | base64 | base64url | raw; secret_encoding: utf8 | ascii | hex | base64 | base64url | raw
```


This is gonna be the default configuration if not specifically defined:

```
payload:
  concat(
    request.headers["webhook-id"],
    ".",
    request.headers["webhook-timestamp"],
    ".",
    request.raw_body
  )

signature_encoding:
  base64
```


For this request it gets the said webhook url:  hook.teamofsilicons.com/silicon/{silicon_id}/{8_digit_alphanumerical}/ along with the 8 digit alphanumerical seperately, if signature is enabled it also gives the signing_secret (`v1`.32 digit alphanumerical) and store it.  

Past creation it should be possible to turn off any single or a set of webhook at any time and still keep it active, and can turn it back on anytime needed.

These configurations can be updated at any given time. The configurations of the signature and signature verification algorithm is also configurable. 


### Rotate Secret

It should also be possible to rotate the signing secret for any webhook. 

### BYOS

Bring your own secret, our system would also support bring your own secret, in which when creating a webhook you can select the verification configuration and then instead of us generating the secret you can also put in your own secret. This can be configured at the time of creation and also past the creation, so it's also possible to set the secret in case of BYOS after the registeration has happened.


# Delete Webhook

A webhook can be deleted by a silicon or org_admins and org_owners. Even deleted webhooks are stored in the delete history for 45 days where they can be recovered from. 


# Request last {n} requests

For an authenticated silicon they should be able to request the last {n} number of requests for a specific webhook. Maximum - 10,000. This would return them the last n request for a specific endpoint. 

They should also be able to do accountwide request where all the last n requests are recieved across all the configured webhooks. 


# Logs

For each endpoint maintain the logs for the requests that have been recieved from that webhook endpoint. Each log would have a TTL of 14 days. This can be viewable at any time by carbon's who have access to the said silicon and the silicon itself. 


# Read

{provider} triggered at HH:MM:SS DD-MM-YYYY IANA_ZONE_ID - this must be included in each hook request that is actuallty sent over, this keeps it clear which provider (name of the hook) sent it and when.

For any new request if the signing for the webhook is enabled, use it to verify based on the defined algorithm and the signature defined to verify the request. Only if the request is verified send it through Ting.


# Safety

If an ip sends 20 requests that were unverified for an signature required webhook endpoint, the said ip would be blocked for 1 day. 


# Accepted

As soon as a webhook request is accepted and stored let the sendee know that the message has been recieved successfully with a webhook.ok endpoint. Store the pending Ting delivery along with the event, so if Ting is unavailable Hook can still receive webhooks and send them later.


# Blocked

Maintain a seperate blocked_logs list, this would include all the unverified logs that weren't sent to the silicon, there should be an endpoint to even read the logs from the blocked_logs, the blocked_logs should have a ttl of 14 days, so only the blocked_logs of recent 14 days would be stored. 


# Delivery

Hook sends events through Ting. Ting handles the shared websocket, local daemon and forwarding to the right silicon or carbon. Hook doesn't need its own delivery websocket or daemon.

The app handles recipient registration and authorization with IAM and Ting internally. No seperate login or delivery setup is needed from the user.


# Acknowledgment

Hook keeps retrying the pending send until Ting confirms it has stored the event, using the same key for retries. Ting handles delivery acknowledgments, retries and reconnects after that. Delivery acknowledgment means the event was received, it doesn't mean the silicon has finished the work.


# OBO

Hook exposes no OBO endpoints. 



# Backend Versioning

For versioning we have Contract Governance/API/service contract lifecycle management. We will have:

1) Contract versioning / API versioning
2) Protocol Negotiation
3) Backward compatibility
4) Consumer-driven contract testing
5) Deprecation and sunset management - if 0 requests for 7 days, sunset that version
6) Compatibility matrix
7) Version policy




# Testing Environment

We will have a test environment for hook itself. This would work exactly like the main application, with the same functions, APIs, permission checks, and workflows, but with completely isolated data.

When a test environment is created, it would start empty.

Honeycomb manages environment creation and lifecycle. Hook prepares its own isolated data when instructed, while IAM still handles test identities, authentication and webhooks.

A test environment is basically the same hook where creating hooks, testing them, etc is possible. It uses test IAM, test hook and test Ting together, so the entire flow can be tested inside one sandbox.

### Environment Lifecycle

Hook would accept authenticated instructions from Honeycomb to prepare, update the key version, clean, disable, restore and permanently remove its test data. Use the shared environment_id, make operations safe to retry and report pending, completed or failed. These instructions must work even when test sessions are disabled.

Cleaning clears the environment's hook endpoints, signing secrets, received events, delivery queues and logs and other test records. Keep Hook linked to the environment so later deletion, restoration and permanent removal still reach it. Check the environment revision and cleaning generation so old incoming requests, Ting deliveries or retries cannot recreate cleared events. Report completion only after Hook's cleanup finishes.

Only allow test access once shared readiness is confirmed, using IAM's current environment state where it enforces this. Disabling blocks access and deliveries immediately; restoring allows access again once ready and does not undo a clean. Report activity for retention decisions instead of independently retiring the environment.

### Using a Test Environment

In the client app, website, CLI, or API, passing the test environment’s `app_secret` would select that application’s test environment. No manual pairing or separately entering the environment root key should be needed. Hook should validate the secret with IAM and identify the correct environment automatically.

For logging in, it would ask for an SLT. In a test environment, this can either be an IAM-issued test SLT or the public ID of an existing Carbon/Silicon in the test sandbox. Entering the ID would sign me in as that test user. Unknown or inactive identities should be rejected. This shortcut must never work in production.

The environment root key gives administrative control over the test world. The application’s `app_secret` selects its sandbox. Once signed in as a particular user, actions must follow that user’s actual permissions. Possessing the secret must not make every signed-in user bypass permission checks.

If an administrative or god view is provided, it should be separate and clearly labelled so it cannot be confused with testing what a normal user is allowed to do.

### Website and CLI

On the website, I should be able to enter the `app_secret` from settings or the sign-in screen. Without a selected test environment, the application would use production.

When in a test environment, always show a banner at the top saying that I am currently in a test environment, along with its name, the signed-in test identity, and a button to exit testing mode.

Production and testing sessions should remain separate. Exiting testing mode should return me to the production session or ask me to sign in.

In the CLI, always display the selected test environment at the end, including when a command fails. This message should go to stderr so it does not interfere with JSON output, downloaded files, or commands used in scripts.

### Isolation

Everything belonging to a test environment must stay inside that environment, including files, permissions, versions, deleted items, search results, caches, notifications, background jobs, and audit logs.

Production credentials must not work in testing, and credentials from one test environment must not work in another.

If a supplied test secret is invalid, revoked, or belongs to an unavailable environment, return an error. Never silently continue in production.

Each test hook URL, event and Ting delivery must resolve to its own environment. Disabled or cleared test endpoints must not accept new events, and test events must never reach production recipients.


### Webhooks and External Actions

Test webhooks should follow IAM’s documented format. Verify the signature over the complete raw body, identify the correct test environment, and apply the event only there. Duplicate or out-of-order events must not corrupt the current state.

Test actions should not send real emails, SMS messages, payments, or other production effects. These should use test destinations or simulated delivery.

Secrets must not appear in URLs, logs, audit records, or stored webhook payloads.


---
---
---
---
---
---
---
---
---
---
---
---
---

Only above this line is what the hook backend would hold, below this would be the users of the backend, the client, the frontend, the cli, etc. 

# Rust Package & CLI

The Rust package & cli using that rust package are for apps integrating with Hook and internal management. Delivery is handled by Ting. the UI will be a subset of the cli. make sure everything works via the CLI first, and then we'll make the UI. Everyone with the required access should be able to use the CLI/Rust Package (carbons, silicons, org, access keys, api keys, read, write, patch, delete, everything).

The rust package would be stateless whereas the cli would be statefull. CLI built on top of the rust package.

For how this CLI is built, rust as the programming language, but can use anything under the hood that is needed. Maybe rust, or node, or shell, as and when the work comes. That is decided by the implementor based on the work. If something requirs a UI (like graph, live, video, images etc). for that the UI has an endpoint that can be viewed/used/downloaded and the cli gives the link to that.

The primary Interface is the Rust Package. CLI is built using the Rust Package only and doesn't have any feature that the Rust package does not.


if you need a local store for auth or something else, use `{home_dir}/.{appname}/dir`.

The default home dir is `~`. If `SILICON_HOME` is present in the enviorment variables, use that as the home directory by default. 

For both package and the cli write detailed docs on how to use the package and how to use the cli, and also another doc on how to use the package. 

Package and CLI must only expose the client side actions, and not the internal actions performed by the backend. For the CLI follow the standard command line grammar rules, and also include a -h command that shows all the possible commands.

Testing in the test enviorment should also be possible via both cli, and the package. 

Testing enviorment in cli, for testing enviorment in cli i should just be able to `hook --test <test_id> <command>` infront of the same command and it should treat that as a test command. Same for test only commands even they would have the same style just without specifying --test for them would return this action is only possible for test enviorment.  

--- logging in via cli ---

For logging in via the cli or the package for any carbon/silicon you don't ask for their credentials or redirect them anywhere, instead you just request for their short lived token. This short lived token would then be used for the same login logic, the short lived token would be compared and you will get the refresh and auth token. 

For CLI login there should be this exact command: `hook login <slt>`. 
And there should be an command to configure the home directory where the information is stored:  `{home_dir}/.{appname}/dir`. This can be confitgure via `hook config home {location}`. If it's not a directory give an error not a directory. 

The Rust client package remains a normal project dependency and does not update itself at runtime. CLI releases and updates follow the Updates section below.

The Hook client and cli don't need a receiving webhook url or a delivery daemon. The app handles Ting delivery setup internally.

It should also expose these specific endpoints:
1) `--help` which would give all the help documentation on how to use hook. So the user should be able to run `hook --help` and get the help docs.
2) `iam --json` the user should be able to run `hook iam --json` which returns `app_id` alongside other information.
3) `login status --json` the user should be able to run `hook login status --json`, reports successful authentication reports `authenticated: true`, alongside which carbon or silicon is it authenticated as.


# Email

We use postmark as our mail provider. You have an email at [hook@teamofsilicons.com], currently this email wont be used for anything more than sending bug reports. 


# Cli experience

CLI is the primary way to manage Hook internally. It should be built for both Carbons & Silicons. Any other interface (like website) will be a subset of the CLI.

The cli should never ask for credentials from either silicon or carbon. it should just ask for short lived tokens that the user can generate from the official iam cli, or from the web where the the user is sent to auth concent screen.

CLIs get SILICON_HOME env variable where it should store all the details. Its home, so you should use that as base, and make their own hidden folders to keep their information.

ISI are internal silicons. If silicon is a brain, then isi are parts of the brain. store this inside metadata, or main data if its super useful. ISI may or may not be present. make sure to not rely on it in such a way that things break. consider ISI as useful additional information.

every app cli must support the following commands:

`app iam --json` gives {app_id: "...", ...}

`app login "..."` takes in a short lived auth token generated by silicon interpretter.

`app login status --json` tells if its {authenticated: true, ...}

Sending events to a silicon is handled internally through Ting, so Hook doesn't need its own webhook/unhook commands for delivery.

App Internals:
Hook has a stateless rust library and a cli built on it. Ting handles the delivery daemon.

On the docs page, show `honeycomb install 'hook'` to install the CLI, followed by how to log in.

CLI design should be focused on giving details and helping finding the right command to use. CLI will often have lots of commands and it should be like a tree that can be traversed using --help.

CLI documentation should be bundled inside the cli itself. On each print of the cli documentation using --help or otherwise, it should show what this command is for, how its often used (perhaps in conjunction with other commands if applicable) and then a list of flags etc it takes in.

Follow the CLI grammar. These CLIs can be used by humans, but more often than not, it'll be used by an agent who prefers to know why something broke and so it can figure out ways to fix it. Don't just say something went wrong... tell it exactly what & why.

A good rule of thumb is: these CLIs are being made for someone who understands ins-and-outs of technology. Make like a programming language that gives very specific and helpful errors and outputs compared to a web interface where all errors are hidden until absolutely critical.

All CLIs must have a report bug feature that also optionally takes in a PR ref if the agent did not just find a bug but also patched it. 

hook report `<report-message>` --pr `<pr-link>` and if someone just reports the bug, without the pr, show them a message, you can also put a pr in the repo (`repo-link`). 

Everytime a bug is reported use postmark to mail [saketdev12@gmail.com, shubhastro2@gmails.com, bugs@teamofsilicons.com]

Since all TOS applications are open sourced, any bug can be discovered, replicated, patched and a pr can be raised. Allow all such edge cases be figured out by the agent instead of fixing it ourselves based on a bug report.

Only a bug report submitting is possible, but its encouraged to give a lot more details and also attach a PR if possible.

Give the information of the github repo, online docs, rust package, etc inside the cli itself.

The CLI as i told before is a tree of documentation. Show possible paths, and then let someone go deeper along with documentation.

Ting handles the shared websocket and local delivery format for the hook events described above.


# Docs

There are two kinds of documentations: informative & instructive.

Always keep instructive documentation up front, easy to use, direct with clear instructions & link to informative documents to know why its done this way. Instructive documents should be the landing point of the product for both carbons & silicons.

For carbons managing Hook internally, it can give instructions on how to install & use it, or how to ask their silicon to use it.

For silicons, it can be that, but also how to do a lot more with it. Esp. things like building on top of it. Make it very clear what is expected, what is mandatory and how does the system work.

Then the silicon can dig deeper into the informative documentation to know all the possible ways to do it, & why its done the way its done.

While both carbons and silicons can read the documentation, it'll likely be more silicon. So design it for silicons. The more reasons you give, the better a silicon would be at making a judgement call of how to do something.

Since all IAM apps can both be used as is, and also built on top of... its imp to write documentation for both. Usage docs & Development docs.

# Telemetry

All IAM apps use Space Station [https://spacestation.teamofsilicons.com/docs] for telemetry. Telemetry is opted-in by default but can be opted out from settings if the user wants.

Space Station is also a rust package which can be used from within the backend, or daemon, or cli to send telemetry.

Record as many things as you think might be useful to diagnose or follow traces later.

Since space station is just an event store, make sure to include all the source, step, progress, etc information inside each event. some of the system information is automatically added to the metadata so you need not add that.

push context-rich, self-contained events.

Space Station also support web, for web it has 2 possible pathways: analytics & events. Most of the Analytics is self captured and you can define a seperate event store from the web. Its possible that both web analytics and web events go to separate tables.


# Configurability

We ship highly configurable apps with sensible defaults. Very much like VS Code. flags to toggle / customize behaviors.


# Updates

For each Hook app release, provide one .tar.gz with honeycomb.yaml at the archive root and the prebuilt hook CLI for Linux, Windows and macOS on x86_64 and aarch64. The manifest maps the hook command to each target's executable and uses the app release version. Run `honeycomb validate` and then `honeycomb pack`. Refer to [Honeycomb docs](https://docs.honeycomb.teamofsilicons.com/) for the package format. Honeycomb handles installation and updates; Hook must not independently replace a Honeycomb-managed CLI.

# Identifier schema

Silicon IDs use `si:{silicon_id}` (for example `si:cos`), Carbon IDs use `c:{carbon_id}` (for example `c:saket`), and application IDs use the bare `{app_id}` (for example `briefcase`). The components after `si:` and `c:` are handles; each prefix appears exactly once. Silicon IDs and application IDs do not contain an organisation component. Organisation membership and application ownership are stored separately under `org_id`.

Outside the schema patterns above, fields and standalone placeholders named `silicon_id`, `sid`, `carbon_id`, or `cid` carry the complete prefixed public ID; `app_id` carries the bare application ID. This applies to authentication, API and CLI inputs and outputs, configuration, permissions, URLs, events and stored identity references. Where a CLI selector uses `@`, it precedes the complete ID, such as `@si:cos` or `@c:saket`.
