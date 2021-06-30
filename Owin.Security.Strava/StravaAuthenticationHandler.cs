using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Owin.Security.Strava
{
    public class StravaAuthenticationHandler : AuthenticationHandler<StravaAuthenticationOptions>
    {
        public const string TokenEndpoint = "https://www.strava.com/oauth/token";
        private const string GraphApiEndpoint = "https://api.foursquare.com/v2/users/self";

        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public StravaAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }
        public override async Task<bool> InvokeAsync()
        {
            if (!String.IsNullOrEmpty(Options.CallbackPath) && Options.CallbackPath == Request.Path.ToString())
            {
                return await InvokeReturnPathAsync();
            }
            return false;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            _logger.WriteVerbose("AuthenticateCore");

            AuthenticationProperties properties = null;
            try
            {
                string code = null;
                string state = null;

                IReadableStringCollection query = Request.Query;
                IList<string> values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }
                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                var tokenRequestParameters = new List<KeyValuePair<string, string>>()
                {
                    new KeyValuePair<string, string>("client_id", Options.ClientId),
                    new KeyValuePair<string, string>("client_secret", Options.ClientSecret),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("grant_type", "authorization_code")
                };

                FormUrlEncodedContent requestContent = new FormUrlEncodedContent(tokenRequestParameters);

                System.Net.ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;

                HttpResponseMessage response = await _httpClient.PostAsync(TokenEndpoint, requestContent, Request.CallCancelled);
                response.EnsureSuccessStatusCode();
                string oauthTokenResponse = await response.Content.ReadAsStringAsync();

                JObject oauth2Token = JObject.Parse(oauthTokenResponse);
                string accessToken = oauth2Token["access_token"].Value<string>();
                string refreshToken = oauth2Token["refresh_token"].Value<string>();
                string expiresAt = oauth2Token["expires_at"].Value<string>();
                string expiresIn = oauth2Token["expires_in"].Value<string>();

                if (string.IsNullOrWhiteSpace(accessToken))
                {
                    _logger.WriteWarning("Access token was not found");
                    return new AuthenticationTicket(null, properties);
                }

                JObject user = (JObject)oauth2Token["athlete"];

                var context = new StravaAuthenticatedContext(Context, user, accessToken);
                context.Identity = new ClaimsIdentity(
                    new[]
                    {
                        new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString, Options.AuthenticationType),
                        new Claim(ClaimTypes.Name, context.Name, XmlSchemaString, Options.AuthenticationType),
                       // new Claim(ClaimTypes.UserData, user.ToString(), XmlSchemaString, Options.AuthenticationType),
                        new Claim("urn:strava:accesstoken", accessToken, XmlSchemaString, Options.AuthenticationType),
                        new Claim("urn:strava:refreshtoken", refreshToken, XmlSchemaString, Options.AuthenticationType),
                        new Claim("urn:strava:expiresat", expiresAt, XmlSchemaString, Options.AuthenticationType),
                        new Claim("urn:strava:expiresin", expiresIn, XmlSchemaString, Options.AuthenticationType),

                    },
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);


                //if (!string.IsNullOrWhiteSpace(context.Email))
                //{
                //    context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, XmlSchemaString, Options.AuthenticationType));
                //}
                //else
                //{
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email, $"{oauth2Token["athlete"]["id"].ToString()}@fitnessviewer.co.uk", XmlSchemaString, Options.AuthenticationType));
                //}
                
                await Options.Provider.Authenticated(context);

                context.Properties = properties;

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteWarning("Authentication failed", ex);
                return new AuthenticationTicket(null, properties);
            }
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            _logger.WriteVerbose("ApplyResponseChallenge");

            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                string baseUri = Request.Scheme + Uri.SchemeDelimiter + Request.Host + Request.PathBase;

                string currentUri = baseUri + Request.Path + Request.QueryString;

                string redirectUri = baseUri + Options.CallbackPath;

                AuthenticationProperties extra = challenge.Properties;
                if (string.IsNullOrEmpty(extra.RedirectUri))
                {
                    extra.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(extra);

                if (Options.Scope.Count == 0)
                    Options.Scope.Add("public"); // Bad request if there is no scope.
                
                // OAuth2 3.3 space separated
                string scope = string.Join(" ", Options.Scope);

                string state = Options.StateDataFormat.Protect(extra);

                string authorizationEndpoint =
                    "https://www.strava.com/oauth/authorize" +
                        "?client_id=" + Uri.EscapeDataString(Options.ClientId) +
                        "&response_type=code" +
                        "&approval_prompt=auto" +
                        "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                        "&scope=" + Uri.EscapeDataString(scope) +
                        "&state=" + Uri.EscapeDataString(state);

                Response.StatusCode = 302;
                Response.Headers.Set("Location", authorizationEndpoint);
            }

            return Task.FromResult<object>(null);
        }

        public async Task<bool> InvokeReturnPathAsync()
        {
            _logger.WriteVerbose("InvokeReturnPath");

            var model = await AuthenticateAsync();

            var context = new StravaReturnEndpointContext(Context, model);
            context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
            context.RedirectUri = model.Properties.RedirectUri;
            model.Properties.RedirectUri = null;

            await Options.Provider.ReturnEndpoint(context);

            if (context.SignInAsAuthenticationType != null && context.Identity != null)
            {
                ClaimsIdentity signInIdentity = context.Identity;
                if (!string.Equals(signInIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                {
                    signInIdentity = new ClaimsIdentity(signInIdentity.Claims, context.SignInAsAuthenticationType, signInIdentity.NameClaimType, signInIdentity.RoleClaimType);
                }
                Context.Authentication.SignIn(context.Properties, signInIdentity);
            }

            if (!context.IsRequestCompleted && context.RedirectUri != null)
            {
                if (context.Identity == null)
                {
                    // add a redirect hint that sign-in failed in some way
                    context.RedirectUri = WebUtilities.AddQueryString(context.RedirectUri, "error", "access_denied");
                }
                Response.Redirect(context.RedirectUri);
                context.RequestCompleted();
            }

            return context.IsRequestCompleted;
        }
        
        private string GenerateRedirectUri()
        {
            string requestPrefix = Request.Scheme + "://" + Request.Host;

            string redirectUri = requestPrefix + RequestPathBase + Options.CallbackPath; // + "?state=" + Uri.EscapeDataString(Options.StateDataFormat.Protect(state));            
            return redirectUri;
        }
    }

}
