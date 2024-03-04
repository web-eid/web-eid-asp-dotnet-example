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
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.IO;
    using System.Security.Claims;
    using System.Security.Cryptography.X509Certificates;
    using digidoc;
    using Dto;
    using Microsoft.Extensions.Logging;
    using WebEid.Security.Util;

    public class SigningService : IDisposable
    {
        private static readonly string FileToSign = Path.Combine("wwwroot", "files", "example-for-signing.txt");
        private readonly DigiDocConfiguration configuration;
        private readonly ILogger logger;
        private bool _disposedValue;

        public SigningService(DigiDocConfiguration configuration, ILogger logger)
        {
            this.configuration = configuration;
            this.logger = logger;
            
            // The current implementation of the static DigiDoc library assumes that SigningService is used as a singleton.
            // In the ASP.NET Core application, we initialize it using the AddSingleton method in Startup.cs.
            // The DigiDoc library is initialized in the constructor and terminated in Dispose.
            configuration.Initialize();
            digidoc.initialize("WebEidExample");
        }

        public DigestDto PrepareContainer(CertificateDto data, ClaimsIdentity identity, string tempContainerName)
        {
            var certificate = new X509Certificate(Convert.FromBase64String(data.CertificateBase64String));
            if (identity.GetIdCode() != certificate.GetSubjectIdCode())
            {
                throw new ArgumentException(
                    "Authenticated subject ID code differs from signing certificate subject ID code");
            }
            
            this.logger?.LogDebug("Creating container file: '{0}'", tempContainerName);
            Container container = Container.create(tempContainerName);
            container.addDataFile(FileToSign, "application/octet-stream");
            logger?.LogInformation("Preparing container for signing for file '{0}'", tempContainerName);
            var signature =
                container.prepareWebSignature(certificate.Export(X509ContentType.Cert), "time-stamp");
                var hashFunction = GetSupportedHashAlgorithm(data.SupportedSignatureAlgorithms, signature.signatureMethod());
            container.save();
            return new DigestDto
            {
                Hash = Convert.ToBase64String(signature.dataToSign()),
                HashFunction = hashFunction
            };
        }

        public void SignContainer(SignatureDto signatureDto, string tempContainerName)
        {
            var container = Container.open(tempContainerName);
            var signatureBytes = Convert.FromBase64String(signatureDto.Signature);
            var signature = container.signatures().First(); // Container must have one signature as it was added in PrepareContainer
            signature.setSignatureValue(signatureBytes);
            signature.extendSignatureProfile("BES/time-stamp");
            container.save();
        }

        private static string GetSupportedHashAlgorithm(IList<SignatureAlgorithmDto> supportedSignatureAlgorithms, string signatureMethod)
        {
            var framgment = new Uri(signatureMethod).Fragment;
            if (supportedSignatureAlgorithms.FirstOrDefault(algo => FragmentEquals(framgment, algo), null) is SignatureAlgorithmDto algo)
            {
                return algo.HashFunction;
            }
            throw new ArgumentException("Supported signature algorithm not found");
        }

        private static bool FragmentEquals(string fragment, SignatureAlgorithmDto signatureAlgorithm) =>
            signatureAlgorithm switch
            {
                { CryptoAlgorithm: "ECC", PaddingScheme: "NONE", HashFunction: "SHA-224" } => fragment == "#ecdsa-sha224",
                { CryptoAlgorithm: "ECC", PaddingScheme: "NONE", HashFunction: "SHA-256" } => fragment == "#ecdsa-sha256",
                { CryptoAlgorithm: "ECC", PaddingScheme: "NONE", HashFunction: "SHA-384" } => fragment == "#ecdsa-sha384",
                { CryptoAlgorithm: "ECC", PaddingScheme: "NONE", HashFunction: "SHA-512" } => fragment == "#ecdsa-sha512",
                { CryptoAlgorithm: "RSA", PaddingScheme: "PKCS1.5", HashFunction: "SHA-224" } => fragment == "#rsa-sha224",
                { CryptoAlgorithm: "RSA", PaddingScheme: "PKCS1.5", HashFunction: "SHA-256" } => fragment == "#rsa-sha256",
                { CryptoAlgorithm: "RSA", PaddingScheme: "PKCS1.5", HashFunction: "SHA-384" } => fragment == "#rsa-sha384",
                { CryptoAlgorithm: "RSA", PaddingScheme: "PKCS1.5", HashFunction: "SHA-512" } => fragment == "#rsa-sha512",
                { CryptoAlgorithm: "RSA", PaddingScheme: "PSS", HashFunction: "SHA-224" } => fragment == "#sha224-rsa-MGF1",
                { CryptoAlgorithm: "RSA", PaddingScheme: "PSS", HashFunction: "SHA-256" } => fragment == "#sha256-rsa-MGF1",
                { CryptoAlgorithm: "RSA", PaddingScheme: "PSS", HashFunction: "SHA-384" } => fragment == "#sha384-rsa-MGF1",
                { CryptoAlgorithm: "RSA", PaddingScheme: "PSS", HashFunction: "SHA-512" } => fragment == "#sha512-rsa-MGF1",
                _ => false
            };
        
        ~SigningService() => Dispose(false);
        
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing) {
                    // You can release managed resources here if needed.
                }

                digidoc.terminate();
                _disposedValue = true;
            }
        }
    }
}
