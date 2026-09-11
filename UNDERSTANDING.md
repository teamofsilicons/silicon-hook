# UNDERSTANIDNG.md - HOOK

This understanding contains everything about how silicon hook would work, and what all is expected from the system. 

So silicon hooks are webhooks on the system that silicons could utilize as webhook connections for various apps. 

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

For every single request sent it should be sent in the format:
```
"type": "new_event",
"data": {
	"sender": "stripe",
	"metadata": {
		metadata here
	}
}
```

Just these 2 feilds must be present in all sent. And metadata included inside data itself.


# Rotate

There should be an endpoint to rotate, which kills the earlier hook url for that particular service instead replaces it with a new endpoint (a new 8 digit alphanumerical that's not already registered for that silicon id) and return it in the same endpoint. The killed endpoint should never be used for the same silicon again 


# Url

Each web hook endpoint would be at [hook.teamofsilicons.com/silicon/{silicon_id}/{8_digit_alphanumerical}]

For eg:
hook.teamofsilicons.com/silicon/cos:tos/402E2J2U

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

# Delete Webhook

A webhook can be deleted by a silicon or org_admins and org_owners. Even deleted webhooks are stored in the delete history for 45 days where they can be recovered from. 


# Request last {n} requests

For an authenticated silicon they should be able to request the last {n} number of requests for a specific webhook. Maximum - 10,000. This would return them the last n request for a specific endpoint. 

They should also be able to do accountwide request where all the last n requests are recieved across all the configured webhooks. 


# Logs

For each endpoint maintain the logs for the requests that have been recieved from that webhook endpoint. Each log would have a TTL of 14 days. This can be viewable at any time by carbon's who have access to the said silicon and the silicon itself. 


# Read

{provider} triggered at HH:MM:SS DD-MM-YYYY IANA_ZONE_ID - this must be included in each hook request that is actuallty sent over, this keeps it clear which provider (name of the hook) sent it and when.

For any new request if the signing for the webhook is enabled, use it to verify based on the defined algorithm and the signature defined to verify the request. Only if the request is verified send it over the websocket connections. 


# Safety

If an ip sends 20 requests that were unverified for an signature required webhook endpoint, the said ip would be blocked for 1 day. 


# Accepted

As soon as a webhook request is recieved let the sendee know that the message has been recieved successfully with a webhook.ok endpoint.  


# Blocked

Maintain a seperate blocked_logs list, this would include all the unverified logs that weren't sent to the silicon, there should be an endpoint to even read the logs from the blocked_logs, the blocked_logs should have a ttl of 14 days, so only the blocked_logs of recent 14 days would be stored. 


# Websocket

We maintain a websocket connection with the client (a client can serve single or multiple silicons/carbons). While authentication they will tell these are the silicon(s) it's trying to connect to.

The server sends an application-level JSON `ping` every 30 seconds. The adapter must immediately reply with a minimal `pong` carrying the same `ping_id`. If no valid pong is received for two minutes, the backend closes with application code `4000` and reason `heartbeat-timeout`. Ping and pong are not stored, do not require ACK, and do not consume per-SID delivery sequences.

The rust client for hook installed for silicon(s) on a local server, starts a daemon locally that would setup the listening endpoint at the time of authentication, this listening endpoint is not sent to the backend this is just for the client/cli to know which port to redirect the requests to for the said silicon. This link is required for client and cli login's. This would be the endpoint that the said silicon listens to so all the messages are reached, for each said message acknowledgment event is send, for each message that silicon desires to send we acknowledge the send along with repeating their exact request.) 


# Acknowledgment

For each hook event that was recieved and sent via websocket or even normal api request must recieve an acknowledged from the server for that particular webhook request that was sent via silicon hook onto the server. For all the unacknowledged webhook events it must automatically be attached in the next websocket connection.


# OBO

Hook exposes no OBO endpoints. 


# Testing

We will have an test enviorment for hook itself, this would be an exact replica of the main application, so when the test enviorment is created it would be initiated empty, for the said test enviorment actions can be performed, as this is an exact same replica of the main prod.

Refer to this to know how to create testing enviorment compatible with iam. 
https://github.com/teamofsilicons/silicon-iam/blob/main/docs/client/testing-environments.html

For creating a test enviorment on hook, it would require the name of the test enviorment and also the test enviroment key of iam, this test iam key would be used in the each request it sends to the IAm as this is in test enviorment, it would in no way be possible to send request to it without attaching the test enviorment. 

So hook testing wouldn't support hook testing on the prod IAm, it would only support it in the testing enviorment of IAm. 

Once the name and the test-key to silicon iam is given, the dm would also generate a test key, this test key can be used by any one to perform any action in silicon-hook. 

For each testing enviorment they would be sharing a shared test database, this would just be an isolated table in the db storing the linking for all the test enviorments.

A test enviorment is basically the exact same hook with all the functions and everything else, so this is the hook where i can test creating a hook, seeing if listening is working, rotating keys, etc.

For each hook in test enviorment would be at hook.teamofsilicons.com/test/silicon/{silicon_id}/{8_digit_alphanumerical}/ 

A maximum of 10 hooks can be created in test enviorment, be clear to mention this is just a test enviorment limitation. 


### Creating Test Env

For creating a test enviorment, it can be created by any carbon or silicon in the organisation and it would be owned by the organisation with the user marked as the creator of the test enviorment. The test enviorment is created at the silicon-hook level itself. For creating a test enviorment it would need the name, an optional description, and the iam test enviorment. 

In return it would return the key for the test enviorment, this key is what's gonna be used to be able to access that test enviorment, anyone with this key would be able to access the test enviorment as the god of the test enviorment, this key would be stored along side with the test enviorment, and can anytime be retrieved by the said carbon/silicon/org_admin/org_owner. The key would be 32 digit alpha numeric. 

### Rotate Key

The creator of the test enviorment and org_admin/org_head should be able to rotate the key of the test enviroment, which would give them a new key to the test enviorment.  

### Clean Test Enviorment

There should be an option to clean the test enviorment, which would allow the test enviorment to be there, but would clear every signle data stored for the said test enviorment. Anyone with the key should be able to execute this action. 

### Delete Test Env

The org admins, owners or the creator should be able to delete the test enviorment, deleting a test enviorment would delete the key, and the instance that the test enviorment even existed. For all the logs it should also be limited to the test enviorment itself. Each deleted Test Env would have a ttl of 30 days before getting deleted permanently. From this point the test env should be recoverable.

### Auto Delete Test Env

If there's no new activity in the test enviorment for 15 days, auto delete the test enviorment. 

### Using a Test Enviorment

For using a test enviorment anyone with the key would have the god view for that test enviorment, they should be able to access hook as the signed in user from IAm, and now as the signed in user it should be able to perform the set of allowed actions, so this is an exact replica of how hook would have worked with the actual iam, instead it has the test hook and the test iam, so an sandboxed enviorment to test it all out. 

Read [(https://github.com/teamofsilicons/silicon-iam/blob/main/docs/client/testing-environments.html)] to understand how exactly are webhooks gonna work for this, etc. 


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

The Rust package & cli using that rust package are first hand client with an always running deamon if needed in the background. the UI will be a subset of the cli. make sure everything works via the CLI first, and then we'll make the UI. Everyone should be able to use the CLI/Rust Package (carbons, silicons, org, access keys, api keys, read, write, patch, delete, everything).

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

For both cli and client we would also package in an auto updater, the task of this auto updater is to compare the current version to the latest version in crates for them, and if there's a new verion auto update it to the said new version. By default auto update is on, users can specifically come and opt in to stop auto update. Which would stop auto updating the package. Auto updater check runs every single hour. Updates should be checked when the command is run and should happen every hour, so check for the last update check time and if it's past 1 hour old check for update and update after the command finishes running.

Whenever someone authenticates as a silicon or carbon the client and cli both would have to give an webhook url to send the data to, so the webhook url would be configured after logging in. The webhook url would be the endpoint where we inform the said silicon or carbon, this is just required in the client and the cli. This endpoint won't be sent to the backend instead stored locally in a file along with the auth in case of cli. The client and cli acts as a relay and a daemon is launched for keeping the websocket connection alive with the backend for it, and when a message comes routing the message to the correct silicon or carbon via the webhook url assigned. And when you get a message to send or any request for that matter, acknowledge that you recieved the message along with the entire request. 

It should also expose these specific endpoints:
1) `--help` which would give all the help documentation on how to use hook. So the user should be able to run `hook --help` and get the help docs.
2) `iam --json` the user should be able to run `hook iam --json` which returns `app_id` alongside other information.
3) `login status --json` the user should be able to run `hook login status --json`, reports successful authentication reports `authenticated: true`, alongside which carbon or silicon is it authenticated as.
4) `webhook <webhook-url>` the user should be able to run `hook webhook <webhook-url>` to configure the webhook endpoint in case of silicon hook, this is the webhook you send all the requests to for that silicon. 
5) `unhook` the user should be able to run `hook unhook` to unhook the configured webhook connection which would simply unhook the said user.

### Cli experience

Cli is an interface on it's own, it's an interface used by our fellow dear agents, and sometimes humans. What we would want this interface to serve as is it should give the correct information at correct time, and can write texts to explain what exactly is happening. 

A few things that would be needed to ensure good cli experience: the cli alone should have enough information to use Hook correctly! Surfacing the right set of things when needed, giving suggestions at the correct times. Like for eg: when someone runs a command then show them the exact help for it if the information is not enough, and when the app has been created, show them the other related commands that they might need to run after it. For each command a good description, the entire docs, etc. 

So the overall cli experience needs to be super good. It needs to give the relevant informations, help should be detailed, and suggested commands, etc should also happen. 

# Docs

The API, Rust-client, CLI, IAM integration, and testing-environment guides are
maintained in [docs/].

For the docs keep it as detailed and mention all the details, this is the only thing the other apps can use as their source of knowledge and how they can use hook exactly. 

Write detailed guides.

Write very good detailed instructions on how test enviorment for silicon-hook works. Write docs on all 3 cli, api, client. Keep it segregated and clear. Write all the documentations in docs/ folder in the main directory of silicon-hook.  

# Later to do

hook report `<report-message>`, this should send an report message to the user. 
