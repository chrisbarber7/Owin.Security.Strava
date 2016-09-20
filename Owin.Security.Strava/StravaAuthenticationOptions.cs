using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Owin.Security;

namespace Owin.Security.Strava
{
    public class StravaAuthenticationOptions : AuthenticationOptions
    {
        public const string Scheme = "Strava";

        public StravaAuthenticationOptions()
            : base(Scheme)
        {
            Caption = Scheme;
            CallbackPath = "/signin-strava";
            AuthenticationMode = AuthenticationMode.Passive;
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            Scope = new List<string>  () { "view_private" };
        }

        public string ClientId { get; set; }

        public string ClientSecret { get; set; }

        public ICertificateValidator BackchannelCertificateValidator { get; set; }
        public TimeSpan BackchannelTimeout { get; set; }
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }

        public string CallbackPath { get; set; }

        public string SignInAsAuthenticationType { get; set; }

        public IStravaAuthenticationProvider Provider { get; set; }

        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        public IList<string> Scope { get; private set; }

    }
}
