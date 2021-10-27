using Microsoft.AspNetCore.Http;
using System.Text.Json;
using WebEid.Security.Challenge;

namespace WebEid.AspNetCore.Example
{
    public class SessionBackedChallengeNonceStore : IChallengeNonceStore
    {
        private const string ChallengeNonceKey = "challenge-nonce";
        private readonly IHttpContextAccessor httpContextAccessor;

        public SessionBackedChallengeNonceStore(IHttpContextAccessor httpContextAccessor)
        {
            this.httpContextAccessor = httpContextAccessor;
        }

        public void Put(ChallengeNonce challengeNonce)
        {
            this.httpContextAccessor.HttpContext.Session.SetString(ChallengeNonceKey, JsonSerializer.Serialize(challengeNonce));
        }

        public ChallengeNonce GetAndRemoveImpl()
        {
            var httpContext = this.httpContextAccessor.HttpContext;
            var challenceNonceJson = httpContext.Session.GetString(ChallengeNonceKey);
            if (!string.IsNullOrWhiteSpace(challenceNonceJson))
            {
                httpContext.Session.Remove(ChallengeNonceKey);
                return JsonSerializer.Deserialize<ChallengeNonce>(challenceNonceJson);
            }
            return null;
        }
    }
}