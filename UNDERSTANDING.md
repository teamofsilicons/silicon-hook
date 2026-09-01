# UNDERSTANIDNG.md - HOOK

This understanding contains everything about how silicon hook would work, and what all is expected from the system. 

So silicon hooks are webhooks on the system that silicons could utilize as webhook connections for various apps. 

# Glossary

`Carbon` - The human in the system. Every human account is called a carbon.
`Silicon` - Our AI Agent (silicon) account is refered to as a Silicon.
`Org` - This is our organisation, this is where all the silicons and carbons would stay for a single organisation and defines the scope. 


# Login

Logging in and signing up are handled entirely by Silicon IAm (this is our access and authorization management layer). You would have an app_id and app_secret stored in your env that you can use to request the login and signup from Silicon IAm (read [[../silicon-iam/UNDERSTANDING.md]]) you would realise how you would need to login and singup using silicon IAm. For both signing in and signing up into the system would need Silicon IAm authorization, once you have the access token from SIlicon IAm for the user logged in, render the application accordingly. 

The webhook endpoint you have would give you information whenever someone logs out, kicked from org, anything changes you would know.

Mainly this will be used by authenticated silicons, so take a look at how silicon's are authenticated and let the silicons do the action accordingly. 

Webhooks are just for silicons to use, and when carbons come into the system for the other silicons that they have authority to view they should be able to open that silicon and see all the active webh ook connections and the logs and the history, etc for that silicon and the specific webhooks. 


# How it works

For any silicon that authenticates onto silicon hook, see if they have a valid silicon account, and if they have a valid silicon account, assign them a silicon hook endpoint. That's gonna be [hook.teamofsilicons.com/{silicon_id}/]. This is the base id that's gonna be used by the silicon for all the webhook endpoints.


# Url

Each web hook endpoint would be at [hook.teamofsilicons.com/silicon/{silicon_id}/{6_digit_hexadecimal}/]

For eg:
hook.teamofsilicons.com/silicon/cos:tos/402E2/


# Create Webhook

A silicon or carbon should be able to create an webhook, for creating an webhook it requires the Name of the service that the webhook is for, and an optional description. For this request it gets the said webhook url:  hook.teamofsilicons.com/silicon/{silicon_id}/{6_digit_hexadecimal}/ along with the 6 digit hexadecimal seperately. 

Past creation it should be possible to turn off any single or a set of webhook at any time and still keep it active, and can turn it back on anytime needed.


# Delete Webhook

A webhook can be deleted by a silicon or org_admins and org_owners. Even deleted webhooks are stored in the delete history for 45 days where they can be recovered from. 


# Request last {n} requests

For an authenticated silicon they should be able to request the last {n} number of requests for a specific webhook. Maximum - 10,000. This would return them the last n request for a specific endpoint. 

They should also be able to do accountwide request where all the last n requests are recieved across all the configured webhooks. 


# Logs

For each endpoint maintain the logs for the requests that have been recieved from that webhook endpoint. Store the last 10,000 requests. This can be viewable at any time by carbon's in charge and silicons. 


# Read

All the Webhook requests would also be sent to silicon-dm webhook along with the silicon it belongs to. 

The reason why we are doing this is so that the said webhook request can actually be conveyed to the said silicon via websocket.


# Websocket

We maintain a websocket connection with the client (a client can serve single or multiple silicons/carbons). While authentication they will tell these are the silicon(s) or carbon(s) it's trying to connect to.

The server sends an application-level JSON `ping` every 30 seconds. The adapter must immediately reply with a minimal `pong` carrying the same `ping_id`. If no valid pong is received for two minutes, the backend closes with application code `4000` and reason `heartbeat-timeout`. Ping and pong are not stored, do not require ACK, and do not consume per-SID delivery sequences.


# Acknowledgment

For each hook event that was recieved and sent via websocket or even normal api request must recieve an acknowledged from the server for that particular webhook request that was sent via silicon hook onto the server. For all the unacknowledged webhook events it must automatically be attached in the next websocket connection.
