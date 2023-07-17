namespace WebEid.AspNetCore.Example.Controllers.Api
{
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Microsoft.AspNetCore.Mvc;
    using Security.Util;
    using Security.Validator;
    using System.Collections.Generic;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Security.Challenge;
    using WebEid.AspNetCore.Example.Dto;
    using System;
    using Microsoft.Extensions.Logging;

    [Route("[controller]")]
    [ApiController]
    public class AuthController : BaseController
    {
        private readonly IAuthTokenValidator authTokenValidator;
        private readonly IChallengeNonceStore challengeNonceStore;
        private readonly ILogger logger;

        public AuthController(IAuthTokenValidator authTokenValidator, IChallengeNonceStore challengeNonceStore, ILogger logger)
        {
            this.authTokenValidator = authTokenValidator;
            this.challengeNonceStore = challengeNonceStore;
            this.logger = logger;
        }

        [HttpPost]
        [Route("login")]
        public async Task Login([FromBody] AuthenticateRequestDto authToken)
        {
            var certificate = await authTokenValidator.Validate(authToken.AuthToken, challengeNonceStore.GetAndRemove().Base64EncodedNonce);

            Dictionary<string, Func<string>> claimDataGetters = new()
            {
                { ClaimTypes.GivenName, certificate.GetSubjectGivenName },
                { ClaimTypes.Surname, certificate.GetSubjectSurname },
                { ClaimTypes.NameIdentifier, certificate.GetSubjectIdCode },
                { ClaimTypes.Name, certificate.GetSubjectCn }
            };

            List<Claim> claims = new();
            foreach (var claimGetter in claimDataGetters)
            {
                try
                {
                    // GivenName and Surname are not presented in case of organization certificates.
                    // Attempt to get these throw ArgumentOutOfRangeException type exception.
                    string claimData = claimGetter.Value.Invoke();
                    claims.Add(new Claim(claimGetter.Key, claimData));
                }
                catch (ArgumentOutOfRangeException)
                {
                    logger.LogWarning("Claim {0} not presented", claimGetter.Key);
                }
            }

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            var authProperties = new AuthenticationProperties
            {
                AllowRefresh = true
            };

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                authProperties);
        }

        [HttpGet]
        [Route("logout")]
        public async Task Logout()
        {
            RemoveUserContainerFile();
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }
    }
}
