//----------------------------------------------------------------------------------------------
//    Copyright 2014 Microsoft Corporation
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//----------------------------------------------------------------------------------------------

// The following using statements were added for this sample.
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Web;
using System.Web.Mvc;

namespace BidTest.Controllers
{
    public class AccountController : Controller
    {
        public void SignIn()
        {
            // Send an OpenID Connect sign-in request.
            if (!Request.IsAuthenticated)
            {
                string login_hint = (string) Session["login_hint"] ?? string.Empty;
                HttpContext.GetOwinContext().Set<string>(OpenIdConnectParameterNames.LoginHint, login_hint);
                string ui_locales = (string)Session["ui_locales"] ?? string.Empty;
                HttpContext.GetOwinContext().Set<string>(OpenIdConnectParameterNames.UiLocales, ui_locales);
                HttpContext.GetOwinContext().Authentication.Challenge(OpenIdConnectAuthenticationDefaults.AuthenticationType);
            }
            else
            {
                HttpContext.Response.Redirect(Startup.redirectUri + "Home/Index");
            }
        }
        public void SignOut()
        {
            // Send an OpenID Connect sign-out request.
            HttpContext.GetOwinContext().Authentication.SignOut(
                OpenIdConnectAuthenticationDefaults.AuthenticationType, 
                CookieAuthenticationDefaults.AuthenticationType);

            HttpContext.Response.Redirect(Startup.redirectUri + "Home/Index");
        }
    }
}