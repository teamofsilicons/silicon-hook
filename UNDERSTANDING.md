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

# Url

Each web hook endpoint would be at [hook.teamofsilicons.com/silicon/{silicon_id}/{6_digit_hexadecimal}/]

For eg:
hook.teamofsilicons.com/silicon/cos:tos/402E2/


# Create Webhook

A silicon or carbon should be able to create an webhook, for creating an webhook it requires the Name of the service that the webhook is for, and an optional description. For this request it gets the said webhook url:  hook.teamofsilicons.com/silicon/{silicon_id}/{6_digit_hexadecimal}/ along with the 6 digit hexadecimal seperately. 


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


# How other apps would use Hook

For other apps configured in IAm they should also be able to use Hook, for that the app would send a request to you to perform as a specific carbon or silicon user, for the said request it would send you app_id and an proof_token. You can send an request to IAm to verify this proof_token by sending it the app_id and the proof_token if it verifies let the application perform the requested action, otherwise deny it. Until the verification is held keep the request alive.  

These authenticated apps should be able to perform all actions on behalf of the user. Except for the delete actions for the files they haven't created. 


# How IAm would use Hook

IAm would issue an anautomatic hook for all the new silicons in the system. This silicon would be with the name Silicon IAM and would be the first default connection for any silicon. 

You must create an internal endpoint for this initiation, only Silicon IAM's authenticated service identity may call this endpoint. Take a read at [[../silicon-iam/UNDERSTANDING.md]]. 

When this request is recieved is when the silicon in the system is registered for that organisation, and the initial webhook is created. 