# demoAuthorizationCodeReceivedSessionNull

this is a demo ASP.NET  project, created by Visual Studio
Enabled Authentication
try to store token in session, but session is null in Startupauth.cs 

         AuthorizationCodeReceived = (context) =>
                {
                            var code = context.Code;
                            var ctx = context.OwinContext.Environment["System.Web.HttpContextBase"] as HttpContextBase;
                            
                            
  running out of ideas
                          
