using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.IdentityModel.Claims;
using System.Threading.Tasks;
using System.Linq;
using System.Web;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Owin.Extensions;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using nochmal5.Models;
using System.Web.SessionState;
using Microsoft.IdentityModel.Tokens;

namespace nochmal5
{
    public partial class Startup
    {
        private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static string appKey = ConfigurationManager.AppSettings["ida:ClientSecret"];
        private static string aadInstance = EnsureTrailingSlash(ConfigurationManager.AppSettings["ida:AADInstance"]);
        private static string authority =  aadInstance + "common"; 
        private ApplicationDbContext db = new ApplicationDbContext();

        // Dies ist die Ressourcen-ID der AAD Graph-API. Diese wird benötigt, um ein Token zum Aufrufen der Graph-API anzufordern.
        private static string graphResourceId = "https://graph.windows.net";

        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            // anstatt die Standardüberprüfung (Überprüfung anhand eines Ausstellerwerts wie in Branchen-Apps) zu verwenden, 
            // wird eigene mehrinstanzenfähige Überprüfungslogik eingefügt
            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                   
                    ClientId = clientId,
                    Authority = authority,
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = false,
                        // Wenn die App Zugriff auf die gesamte Organisation benötigt, dann fügen Sie die Logik
                        // zum Überprüfen des Ausstellers hier ein.
                        // IssuerValidator
                    },
                    Notifications = new OpenIdConnectAuthenticationNotifications()
                    {
                         
                         SecurityTokenValidated = (context) =>
                        {
                            // Wenn Ihre Authentifizierungslogik auf Benutzern basiert,
                            return Task.FromResult(0);
                        },
                        
                        AuthorizationCodeReceived = (context) =>
                        {
                            var code = context.Code;
                            var ctx = context.OwinContext.Environment["System.Web.HttpContextBase"] as HttpContextBase;
                            var s = ctx.Session;
                            ClientCredential credential = new ClientCredential(clientId, appKey);
                            string tenantID = context.AuthenticationTicket.Identity.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid").Value;
                            string signedInUserID = context.AuthenticationTicket.Identity.FindFirst(ClaimTypes.NameIdentifier).Value;

                            AuthenticationContext authContext = new AuthenticationContext(aadInstance + tenantID, new ADALTokenCache(signedInUserID));
                            AuthenticationResult result = authContext.AcquireTokenByAuthorizationCodeAsync(
                                code, new Uri(HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Path)), credential, graphResourceId).Result;

                            return Task.FromResult(0);
                        }
                    }
                });

            // Auf diese Weise wird Middleware, die oberhalb dieser Zeile definiert ist, ausgeführt, bevor die Autorisierungsregel in "web.config" angewendet wird.
            app.UseStageMarker(PipelineStage.Authenticate);


//überflüssig
            //app.Use((context, next) =>
            //{
            //    var httpContext = context.Get<HttpContextBase>(typeof(HttpContextBase).FullName);
            //    httpContext.SetSessionStateBehavior(SessionStateBehavior.Required);
            //    return next();
            //});

            //// To make sure the above `Use` is in the correct position:
            //app.UseStageMarker(PipelineStage.AcquireState);
        }

        private static string EnsureTrailingSlash(string value)
        {
            if (value == null)
            {
                value = string.Empty;
            }

            if (!value.EndsWith("/", StringComparison.Ordinal))
            {
                return value + "/";
            }

            return value;
        }
    }
}
