using Microsoft.IdentityModel.Protocols;
using Newtonsoft.Json.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace BidTest.Controllers
{

    public class HomeController : Controller
    {
        /// <summary>
        /// Call the OpenID Connect UserInfo endpoint/REST api 
        /// </summary>
        /// <param name="token">The access_token giving access to the UserInfo resource</param>
        /// <returns>Result JSON object</returns>
        // 
        private async Task<JObject> CallUserInfo(string token)
        {
            string json = string.Empty;
            using (var client = new System.Net.Http.HttpClient())
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
                json = await client.GetStringAsync(Startup.OIDC_baseUrl + "userinfo");
            }
            return JObject.Parse(json);
        }

        public string allowed_scopes = string.Empty;

        [Route("~/")]
        [Route]
        [Route("Index")]
        public async Task<ActionResult> Index()
        {
            var identity = (ClaimsIdentity)ClaimsPrincipal.Current.Identity;

            if (identity != null && identity.IsAuthenticated)
            {
                var access_token = identity.FindFirst(OpenIdConnectParameterNames.AccessToken);
                var id_token = identity.FindFirst(OpenIdConnectParameterNames.IdToken);

                if (access_token == null)
                {
                    ViewBag.Message1 = "access_token: wasn't received!";
                }
                else
                {
                    JObject userInfo = await CallUserInfo(access_token.Value);
                    ViewBag.Title1 = "Fra UserInfo:";
                    ViewBag.Message1 = userInfo.ToString();
                }

                ViewBag.Title2= OpenIdConnectParameterNames.IdToken;
                ViewBag.Message = id_token == null ? "No id_token!" : id_token.Value;
                var allowed_scopes = identity.FindFirst("allowed_scopes");
                ViewBag.allowed_scopes = identity.FindFirst("allowed_scopes") == null ? string.Empty: allowed_scopes.Value;
            }
            return View();
        }
        [AllowAnonymous]
        [HttpGet]
        public ActionResult SetLoginHint(string login_hint)
        {
            if (login_hint != null && login_hint.Length > 2)
            {
                Session["login_hint"] = login_hint.Replace("'", string.Empty).Trim();
            }
            else
            {
                Session["login_hint"] = string.Empty;
            }
            return RedirectToAction("Index", "Home");
        }
        [AllowAnonymous]
        [HttpGet]
        public ActionResult SetUiLocales(string ui_locales)
        {
            if (ui_locales != null && ui_locales.Length > 1)
            {
                Session["ui_locales"] = ui_locales.Replace("'", string.Empty).Trim();
            }
            else
            {
                Session["ui_locales"] = string.Empty;
            }
            return RedirectToAction("Index", "Home");
        }
        public ActionResult Error(string message)
        {

            ViewBag.Message = message; 
            return View("~/Views/Shared/Error.cshtml"); 
        }
    }
}