using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Newtonsoft.Json.Linq;
using Owin;
using System.Collections.Generic;
using System.Configuration;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Web;

namespace BidTest
{
    public partial class Startup
    {
        //
        // The Client ID is used by the application to uniquely identify itself to BID OIDC.
        // The Metadata Address is used by the application to retrieve the signing keys used by BID OIDC.
        //
        public readonly static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        public readonly static string clientSecret = ConfigurationManager.AppSettings["ida:ClientSecret"];
        public readonly static string OIDC_baseUrl = ConfigurationManager.AppSettings["ida:OIDC_BaseUrl"];
        public readonly static string redirectUri = ConfigurationManager.AppSettings["ida:RedirectUri"];
        public readonly static string manifestUrl = OIDC_baseUrl + ".well-known/openid-configuration";
        public readonly static string authenticationType = "BankID";
        public readonly static string scope = ConfigurationManager.AppSettings["ida:Scope"];

#if true // DEBUG
        // The following method is invoked by the RemoteCertificateValidationDelegate.
        public static bool AcceptAllCertifications(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true; // Allow self signed cert's
        }
#endif

        public void ConfigureAuth(IAppBuilder app)
        {
#if true // DEBUG
            // Accept self signed SSL certificates
            ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(AcceptAllCertifications);
#endif
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);
            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            var options = new OpenIdConnectAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret,
                Authority = OIDC_baseUrl,
                RedirectUri = redirectUri,
                MetadataAddress = manifestUrl,
                ResponseType = "code id_token",     // This code may crash if you change ResponseType
                Scope = Startup.scope,
                SignInAsAuthenticationType = "Cookies",

                Notifications = new OpenIdConnectAuthenticationNotifications
                {
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

                    AuthorizationCodeReceived = async (context) =>
                    {
                        // Here we have an authorization_code and needs to get the access_token. 
                        await GetAccessTokenAndStoreWithIdentity(context);
                    },

                    AuthenticationFailed = context =>
                    {
                        context.Response.Redirect(redirectUri + "Home/Error?message=" + context.Exception.Message);
                        return Task.FromResult(0);
                    },
                    
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
            };

            app.UseOpenIdConnectAuthentication(options);
        }

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
                Dictionary<string, string> reqDictionary = new Dictionary<string, string>
                {
                    { OpenIdConnectParameterNames.ClientId, context.Options.ClientId },
                    { OpenIdConnectParameterNames.ClientSecret, context.Options.ClientSecret },
                    { OpenIdConnectParameterNames.Code, context.ProtocolMessage.Code },
                    { OpenIdConnectParameterNames.GrantType, "authorization_code" },
                    { OpenIdConnectParameterNames.RedirectUri, context.Options.RedirectUri }
                };


                request.Content = new FormUrlEncodedContent(reqDictionary);

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
    }

}