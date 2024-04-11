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

    [Route("[controller]")]
    [ApiController]
    public class AuthController : BaseController
    {
        private readonly IAuthTokenValidator authTokenValidator;
        private readonly IChallengeNonceStore challengeNonceStore;

        public AuthController(IAuthTokenValidator authTokenValidator, IChallengeNonceStore challengeNonceStore)
        {
            this.authTokenValidator = authTokenValidator;
            this.challengeNonceStore = challengeNonceStore;
        }

        [HttpPost]
        [Route("login")]
        public async Task Login([FromBody] AuthenticateRequestDto authToken)
        {
            var certificate = await this.authTokenValidator.Validate(authToken.AuthToken, this.challengeNonceStore.GetAndRemove().Base64EncodedNonce);
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.GivenName, certificate.GetSubjectGivenName()),
                new Claim(ClaimTypes.Surname, certificate.GetSubjectSurname()),
                new Claim(ClaimTypes.NameIdentifier, certificate.GetSubjectIdCode())
            };

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            var authProperties = new AuthenticationProperties
            {
                AllowRefresh = true
            };

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                authProperties);
            
            // Assign a unique ID within the session to enable the use of a unique temporary container name across successive requests.
            // A unique temporary container name is required to facilitate simultaneous signing from multiple browsers.
            SetUniqueIdInSession();
        }

        [HttpGet]
        [Route("logout")]
        public async Task Logout()
        {
            RemoveUserContainerFile();
            await HttpContext.SignOutAsync(
                CookieAuthenticationDefaults.AuthenticationScheme);
        }
    }
}
