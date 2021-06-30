using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using System;
using System.Security.Claims;

namespace Owin.Security.Strava
{
    public class StravaAuthenticatedContext : BaseContext
    {
        public StravaAuthenticatedContext(IOwinContext context, JObject user, string accessToken)
            : base(context)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            
            User = user;
            AccessToken = accessToken;

            JToken userId = User["id"];
            if (userId == null)
            {
                throw new ArgumentException("The user does not have an id.", "user");
            }

            Id = TryGetValue(user, "id");
            FirstName = TryGetValue(user, "firstname");
            LastName = TryGetValue(user, "lastname");
            Name = FirstName + " " + LastName;
            Gender = TryGetValue(user, "sex");
            HomeCity = TryGetValue(user, "city");
            HomeState = TryGetValue(user, "state");
            HomeCountry = TryGetValue(user, "country");
            Photo = TryGetValue(user, "profile");
            PhotoMedium = TryGetValue(user, "profile_medium");
            FollowerCount = TryGetValue(user, "follower_count");
            FriendCount = TryGetValue(user, "friend_count");
            //Email = TryGetValue(user, "email");
            Premium = TryGetValue(user, "premium");
            CreatedAt = TryGetValue(user, "created_at");
            UpdatedAt = TryGetValue(user, "updated_at");
            MeasurementPreference = TryGetValue(user, "measurement_preference");
            DatePreference = TryGetValue(user, "date_preference");
            Link = "http://www.strava.com/athletes/" + Id;          
        }

        public JObject User { get; private set; }
        public string AccessToken { get; private set; }
        public string Id { get; private set; }
        public string FirstName { get; private set; }
        public string LastName { get; private set; }
        public string Name { get; private set; }
        public string Gender { get; private set; }
        public string HomeCity { get; private set; }
        //public string Email { get; private set; }
        public string Link { get; private set; }
        public string HomeState { get; private set; }
        public string HomeCountry { get; private set; }
        public string Photo { get; private set; }
        public string PhotoMedium { get; private set; }
        public string FollowerCount { get; private set; }
        public string FriendCount { get; private set; }
        public string Premium { get; private set; }
        public string CreatedAt { get; private set; }
        public string UpdatedAt { get; private set; }
        public string MeasurementPreference { get; private set; }
        public string DatePreference { get; private set; }

        public ClaimsIdentity Identity { get; set; }
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
    }
}
