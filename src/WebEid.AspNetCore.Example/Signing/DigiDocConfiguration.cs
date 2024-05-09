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

﻿namespace WebEid.AspNetCore.Example.Services
{
    using digidoc;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.Extensions.Hosting;
    using System;

    public class DigiDocConfiguration
    {
        /// <summary>
        /// Base64 cert from https://open-eid.github.io/test-TL/trusted-test-tsl.crt
        /// </summary>
        private const string TestTslCert = @"MIIEvDCCAqQCCQCL/COUVyiGjTANBgkqhkiG9w0BAQUFADAgMQswCQYDVQQGEwJF
RTERMA8GA1UEAwwIVGVzdCBUU0wwHhcNMTgxMTE1MTI1MjU1WhcNMjgxMTEyMTI1
MjU1WjAgMQswCQYDVQQGEwJFRTERMA8GA1UEAwwIVGVzdCBUU0wwggIiMA0GCSqG
SIb3DQEBAQUAA4ICDwAwggIKAoICAQDfFK0fYeGrdngMZXZndDEpcl9pjGGNpbie
3+ch5mDqObUe+OL45b4+SfPapriVRNBa+m5T1TuijP7Kb8sTNS9U3WQYvY8bEstP
ZnaEvdQSSVRf4j9eVg+RTJ8Y4jjZ02GbLwrpELD2Qs+ohCl8e64G29qutchv6nJq
OdbL5U+d6DKyrzSpZyMRPA+UmB78KsBTs0o3wME7IA9J37YgtpUZifcC4LdgTWrX
2eBICGPqi7GGKzdnI5LDhCJZnHwzva+6lBwa8fW5aXQG69uPTFmd/pNNF6+8f2Fc
YGljQiD6FYVKAUfYRBlw9ymKaIbNmyh9bs71ezPrI4ltOLjmZLZFRouSIaeExfzj
2FkWERNG/iAuEIRolyyXjqjiQIuiEi8uo6sg1cPrD59EuWtTcMzTxuhVU8Ra37F6
DrMEipqh84zQcnT0i/RNk4K723aB9uWwHJgJ5Y2/6cbta7ZkYsfQfjBC4nBRVyUl
BCpEFYNePbKttYF5Cf5FraMlGzAY0W/MSIUxvRmlkjCzBod4LA+K/hQxEiw7Xa8O
AZfw9l9lmSnia+fgRz3fLKxg3yklw6rA/2aISb83uVRvxgqKym3EeJ/+CsOQpwOb
lEBxWfQizah1Ct4NhsuKLmBbopxAXLqz25E+3BvvsM4nuwWVfoyvTVXYQ+k4V/hj
2iS5buJ5twIDAQABMA0GCSqGSIb3DQEBBQUAA4ICAQAGTw5MJurTeeWy+jQikGfi
vrxt9lzqt+uSV8D6V1GBzBAl8m4SqSY0U8KM/gtqh9bhmQwm0qgx/mKcDKzCUKaj
XPKm/NbR+pjZD9Lcx4Iy0iqi9rsxSKECGM2dYAmm7GXnXvz9QUxZjteTgYoRP2s6
GfosvTQiUEr/cIrYAU3wC0/94pRb9/FLVVon/aVdsh+Dqb4j7BhKLzXNCNjkv1Sv
/YL1zpe/2SPxe0Bfymys97lcu1DB01e/MLfqQJThYOblMte/zGNZO24HcvROIkyo
UtYy5/H4F5rsamSGMNdBfauTtYxz7lOT7qQoDNyGMN9bfjWnkVi/lV2CVooeiHIs
7wLWEhYmU9DiAzcmODU9uMRRBlGOWK8UQg05exc518heICmudSbgSyQLGqzVoI4k
ybhmBA3w93KEXJSXlnU7hBzoYDP2d1g46Ay59UtvLycS1kxe0jVjxxRnh/f9aPbM
wUYBzEC0naUzMeJtElHLHgW4HT6PLgFImgLLFh8dnYJUzn35wz10g3YBA61YUJuO
DpapKHixn/2X/t/8Vf1vqr/VwiwUglNQj+P78Fdb3T56JsYRG1bdf6nz5dvv4qtL
oG+OjPI/tiLjh2ktqaMjeVmlQFchy/C5Lr48d9IGmo+x2ECYSWVvwzxI7PIbYBI4
oaPjh2zKIrz/AlY2RmqMMA==";
        private const string TestTslUrl = "https://open-eid.github.io/test-TL/tl-mp-test-EE.xml";
        private const string TestTsUrl = "http://demo.sk.ee/tsa/";

        private readonly IWebHostEnvironment env;

        public DigiDocConfiguration(IWebHostEnvironment env)
        {
            this.env = env;
        }

        public void Initialize()
        {
            var conf = new DigiDocConf("");
            if (env.IsDevelopment())
            {
                conf.setTSLUrl(TestTslUrl);
                conf.setTSLCert(Convert.FromBase64String(TestTslCert));
                conf.setTSUrl(TestTsUrl);
            }
            DigiDocConf.init(conf);
        }
    }
}
