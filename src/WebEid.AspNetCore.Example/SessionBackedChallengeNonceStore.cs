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
