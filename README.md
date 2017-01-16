# BankID Test Application for BankID Norge AS
This is a .NET based test application for authenticating a user with BankID OpenID Connect Server (BID OIDC) developed for BankID Norge AS.
When the user is authenticated you will see the result from a call to UserInfo RESTful service and the contents of the id_token which was returned from BID OIDC.

## Authentication and Authorization
The OWIN framework - Open Web Interface for .NET \([read about OWIN](http://owin.org/)\) \- talks OpenID Connect protocol with BID OIDC.  
The most interesting code for this example is in the startup module **App_Start\Startup.Auth.cs** where you will find configuration of OWIN.
After authentication and authorization of the end user this test application will show the contents of id_token and response from UserInfo RESTful API.
This is done in **HomeController.cs** (with the help of some view files).

## BankID OpenID Connect Server Specifics
BID OIDC talks standard OpenID Connect and OAUTH2 authorization. The server is designed to be used directly or as an Identity Provider (IdP) for Microsoft Azure AD B2C (AAD/B2C).
We have had to add some custom parameters in order to pass information from the Client to BID OIDC through AAD/B2C. AAD/B2C is using the same protocols and parameters
like client\_id, login\_hint and ui\_locales all have meaning to AAD/B2C. For the Client to pass those parameters through AAD/B2C to BID OIDC one can simply prefix parameters
with bid\_ (eg. bid\_login\_hint). These are custom parameters that AAD/B2C just passes on to BID OIDC, but which works like the equivalent standard parameters in BID OIDC.

## Client_id - Client Definitions
In order to use BID OIDC one has to apply for getting a Client ID from BID OIDC. Here are some specifics for clients:

| Parameter        | Comment                                                                                            |
|------------------|----------------------------------------------------------------------------------------------------|
| clientId         | Unique identifier for THIS client                                                                  |
| clientSecret     | A password used with clientId when requesting an access_token.                                     |
| applicationName  | Name of the client application shown in GUI (for instance when deciding what scopes to allow the Client to use). |
| redirectUris     | A list of URIs to legal redirects. This is where the Client regains control after BID OIDC has reponded to the authorization request. Default for this test application will use redirectUri https://localhost:44320
| registeredScopes | A list of scopes/resources this client may use. BID OIDC offers scopes like: nnin, standard_bankid, address, phone, openid. |
| properties       | This is a list of name/value pairs. For BID OIDC: |
|                  | bidmerchant/standardmerchant: This defines which merchant the authentication is in context of. |
|                  | presentationUrl/https://... : Pointer to an external server that presents GUI for the dialogs during authentication and scope consent. |


## Login_hint syntax
Login_hint is an optional parameter enabling the Client to pass preferred BankID authentication method to BID OIDC. In addition the Client may pass Norwegian National Identity Number
(nnin - fødselsnummer) or phone number and birhtday if this is known to the Client. The syntax for this is as follows:
```RegExp
[BIM|BID][:\d{11}][:\d{8}][:\d{6}] for respectively client_type, nnin, phoneNo, birthday (Case sensitive).
```


| Examples | Comment |
| --- | --- |
| BID | Use Banklagret BankID (net centric BankID) for authentication |
| BID:09038012345 | Use Banklagret BankID and use 09038012345 for nnin - go direct to prompting for one time password. |
| BIM | Use BankID på Mobil (cell phone authentication). The user will be prompted for phone number and birthday |
| BIM:49090909:090380 | Use BankID på Mobil. Phone number and birthday is passed along. The user will see the code words to validate in the cell phone message. | 
| :09038012345:49090909 | This is a legal login_hint where the user can pick which BankID to use for authentication, and nnin, phone number and birthday is prefilled in the form. |
 

## Configuration
In Web.config you will need to set the following parameters:
```xml
    <!-- Definitions for OpenID Connect -->
    <add key="ida:ClientId" value="........" />    <!-- This is the client_id discussed abowe -->
    <add key="ida:ClientSecret" value="......" />     <!-- This is the password associated with the client_id -->
    <add key="ida:OIDC_BaseUrl" value="https://prototype.kantega.no/bankid-oauth/oauth/" />    <!-- Base address of BID OIDC -->
    <add key="ida:RedirectUri" value="https://localhost:44320/" />      <!-- Where to return with results from BID OIDC authorization request -->
    <add key="ida:Scope" value="openid standard_bankid nnin address" /> <!-- Scopes used in this application -->
```

## Comments on Code 
In **App_Start\Startup.Auth.cs** we add some custom code. As you see below OWIN sends _notifications_ for special events. We have set up to catch some of these notifications.
_RedirectToIdentityProvider_ happens when OWIN is requesting authorization. Here we may add our extra parameters:
```
    RedirectToIdentityProvider = context =>
    {
        // Note! OWIN uses response_mode == "form_post" - not the default fragment!
        if (context.ProtocolMessage.RequestType ==  OpenIdConnectRequestType.AuthenticationRequest)
        {
            // Add custom parameters for BID OIDC here:
            string login_hint = context.OwinContext.Get<string>(OpenIdConnectParameterNames.LoginHint);
            if (!string.IsNullOrEmpty(login_hint))
            {
                // If going thru Azure AD/B2C we need to use custom login_hint:
                // BankID OIDC server treats bid_login_hint as login_hint
                context.ProtocolMessage.Parameters.Add(OpenIdConnectParameterNames.LoginHint, login_hint);
            }
            string ui_locales = context.OwinContext.Get<string>(OpenIdConnectParameterNames.UiLocales);
            if (!string.IsNullOrEmpty(ui_locales))
            {
                context.ProtocolMessage.Parameters.Add(OpenIdConnectParameterNames.UiLocales, ui_locales);
            }
        }
        return Task.FromResult(0);
    },
```
_SecurityTokenValidated_ happens when the id_token is accepted. OWIN has created a _context.AuthenticationTicket.Identity_ but it doesn't recognize
 the name claims returned from BID OWIN. We need to set a name claim and also ensure that the unique ID returned from BankID is available.

```
        SecurityTokenValidated = context =>
        {
            var ident = context.AuthenticationTicket.Identity;

            // OWIN Middleware translates claim types from BID's id_token:
            // "sub" becomes "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"
            // "dateofbirth" becomes "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/dateofbirth"
            // Make a copy of the BankID unique ID to be on the safe side (don't trust AAD to keep off)
            Claim bid = ident.FindFirst(System.IdentityModel.Claims.ClaimTypes.NameIdentifier);
            if (bid != null)
            {
                context.AuthenticationTicket.Identity.AddClaim(
                    new Claim(
                        "bid_id",
                        bid.Value,
                        bid.ValueType,
                        bid.Issuer,
                        bid.OriginalIssuer,
                        bid.Subject
                    ));
            }

            // Ensure that this identity has got a name
            Claim userName = ident.FindFirst("preferred_username") ?? ident.FindFirst("name");
            if (userName != null)
            {
                context.AuthenticationTicket.Identity.AddClaim(new Claim(ident.NameClaimType, userName.Value));
            }

            return Task.FromResult(0);
        }
    }
 ```
As OWIN, the version we use here, does not automatically fetch an access_token after authorization_code is received, we need to listen for 
_AuthorizationCodeReceived_ notification. We do the token request and save the access_token for later use and we also get a list of scopes that were accepted by the end user.
```
        AuthorizationCodeReceived = async (context) =>
        {
            // Here we have an authorization_code and needs to get the access_token. 
            await GetAccessTokenAndStoreWithIdentity(context);
        },

        //
        // Call the OAuth2 token endpoint to get an access_token and accepted scopes and add to identity's claims.
        //
        private async Task GetAccessTokenAndStoreWithIdentity(AuthorizationCodeReceivedNotification context)
        {
            string access_token = string.Empty;
            string allowed_scopes = string.Empty;

            // Save id_token for display in HomeController 
            // (id_token is allready used to build this identity, but we want the unaltered version).
            string id_token = context.JwtSecurityToken.ToString();
            context.AuthenticationTicket.Identity.AddClaim(new Claim(OpenIdConnectParameterNames.IdToken, id_token));

            using (var client = new HttpClient())
            {
                var configuration = await context.Options.ConfigurationManager.GetConfigurationAsync(context.Request.CallCancelled);

                var request = new HttpRequestMessage(HttpMethod.Post, configuration.TokenEndpoint);
                request.Content = new FormUrlEncodedContent(
                    new Dictionary<string, string>
                    {
                    { OpenIdConnectParameterNames.ClientId, context.Options.ClientId },
                    { OpenIdConnectParameterNames.ClientSecret, context.Options.ClientSecret },
                    { OpenIdConnectParameterNames.Code, context.ProtocolMessage.Code },
                    { OpenIdConnectParameterNames.GrantType, "authorization_code" },
                    { OpenIdConnectParameterNames.RedirectUri, context.Options.RedirectUri }
                    });

                HttpResponseMessage response = null;
                try
                {
                    response = await client.SendAsync(request, context.Request.CallCancelled);
                    response.EnsureSuccessStatusCode();

                }
                catch (System.Exception e)
                {
                    string message = e.Message;
                    context.Response.Redirect(redirectUri + "Home/Error?message=" + HttpUtility.UrlPathEncode(message));
                    return;
                }
                var payload = JObject.Parse(await response.Content.ReadAsStringAsync());
                access_token = payload.Value<string>(OpenIdConnectParameterNames.AccessToken) ?? string.Empty;
                allowed_scopes = payload.Value<string>(OpenIdConnectParameterNames.Scope) ?? string.Empty;

            }

            context.AuthenticationTicket.Identity.AddClaim(new Claim(OpenIdConnectParameterNames.AccessToken, access_token));
            context.AuthenticationTicket.Identity.AddClaim(new Claim("allowed_scopes", allowed_scopes));
        }

```

