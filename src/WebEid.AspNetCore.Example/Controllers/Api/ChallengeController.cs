namespace WebEid.AspNetCore.Example.Controllers.Api
{
    using Microsoft.AspNetCore.Mvc;
    using Security.Challenge;
    using System;
    using WebEid.AspNetCore.Example.Dto;

    [Route("auth")]
    [ApiController]
    public class ChallengeController : BaseController
    {
        private readonly IChallengeNonceGenerator challengeNonceGenerator;

        public ChallengeController(IChallengeNonceGenerator challengeNonceGenerator)
        {
            this.challengeNonceGenerator = challengeNonceGenerator;
        }

        [HttpGet]
        [Route("challenge")]
        public ChallengeDto GetChallenge()
        {
            var challenge = new ChallengeDto
            {
                Nonce = challengeNonceGenerator.GenerateAndStoreNonce(TimeSpan.FromMinutes(5)).Base64EncodedNonce
            };
            return challenge;
        }
    }
}
