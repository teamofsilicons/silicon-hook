# UNDERSTANIDNG.md - HOOK

This understanding contains everything about how silicon hook would work, and what all is expected from the system. 

So silicon hooks are webhooks on the system that silicons could utilize as webhook connections for various apps. 

# Glossary

`Carbon` - The human in the system. Every human account is called a carbon.
`Silicon` - Our AI Agent (silicon) account is refered to as a Silicon.
`Org` - This is our organisation, this is where all the silicons and carbons would stay for a single organisation and defines the scope. 


# Login

Logging in and signing up are handled entirely by Silicon IAm (this is our access and authorization management layer). You would have an app_id and app_secret stored in your env that you can use to request the login and signup from Silicon IAm (read [https://backend.iam.teamofsilicons.com/docs/client/]) you would realise how you would need to login and singup using silicon IAm. For both signing in and signing up into the system would need Silicon IAm authorization, once you have the access token from SIlicon IAm for the user logged in, render the application accordingly. 

Install the silicon IAm's package via crate, and use it's client side docs. 

The webhook endpoint you have would give you information whenever someone logs out, kicked from org, anything changes you would know.

Mainly this will be used by authenticated silicons, so take a look at how silicon's are authenticated and let the silicons do the action accordingly. 

Webhooks are just for silicons to use, and when carbons come into the system for the other silicons that they have authority to view they should be able to open that silicon and see all the active webh ook connections and the logs and the history, etc for that silicon and the specific webhooks. 


# How it works

For any silicon that authenticates onto silicon hook, see if they have a valid silicon account, and if they have a valid silicon account. This is the base id that's gonna be used by the silicon for all the webhook endpoints.

There should be an endpoint to get all the hooks, it should return the name of the hook, the hook url, and when it last reached out.


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


For this request it gets the said webhook url:  hook.teamofsilicons.com/silicon/{silicon_id}/{6_digit_alphanumerical}/ along with the 8 digit alphanumerical seperately, if signature is enabled it also gives the signing_secret (`v1`.32 digit alphanumerical) and store it.  

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


# Acknowledgment

For each hook event that was recieved and sent via websocket or even normal api request must recieve an acknowledged from the server for that particular webhook request that was sent via silicon hook onto the server. For all the unacknowledged webhook events it must automatically be attached in the next websocket connection.


# OBO

Hook exposes no OBO endpoints. 