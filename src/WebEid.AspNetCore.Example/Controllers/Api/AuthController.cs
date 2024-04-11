// Copyright (c) 2021-2024 Estonian Information System Authority
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

﻿namespace WebEid.AspNetCore.Example.Controllers.Api
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
