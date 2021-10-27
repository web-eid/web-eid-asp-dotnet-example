namespace WebEid.AspNetCore.Example.Services
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Claims;
    using System.Security.Cryptography.X509Certificates;
    using digidoc;
    using Dto;
    using Microsoft.Extensions.Logging;
    using WebEid.Security.Util;

    public class SigningService
    {
        private const string FileToSign = @"wwwroot\files\example-for-signing.txt";
        private readonly DigiDocConfiguration configuration;
        private readonly ILogger logger;

        public SigningService(DigiDocConfiguration configuration, ILogger logger)
        {
            this.configuration = configuration;
            this.logger = logger;
        }

        public DigestDto PrepareContainer(CertificateDto data, ClaimsIdentity identity, string tempContainerName)
        {
            var certificate = new X509Certificate(Convert.FromBase64String(data.CertificateBase64String));
            if (identity.GetIdCode() != certificate.GetSubjectIdCode())
            {
                throw new ArgumentException(
                    "Authenticated subject ID code differs from signing certificate subject ID code");
            }

            configuration.Initialize();
            digidoc.initialize("WebEidExample");
            try
            {
                this.logger?.LogDebug("Creating container file: '{0}'", tempContainerName);
                Container container = Container.create(tempContainerName);
                container.addDataFile(FileToSign, "application/octet-stream");
                logger?.LogInformation("Preparing container for signing for file '{0}'", tempContainerName);
                var signature =
                    container.prepareWebSignature(certificate.Export(X509ContentType.Cert), "BES/time-stamp");
                container.save();
                return new DigestDto
                {
                    Hash = Convert.ToBase64String(signature.dataToSign()),
                    HashFunction = GetSupportedHashAlgorithm(data.SupportedSignatureAlgorithms)
                };
            }
            finally
            {
                digidoc.terminate();
            }
        }


        public void SignContainer(SignatureDto signatureDto, string tempContainerName)
        {
            configuration.Initialize();
            digidoc.initialize("WebEidExample");
            try
            {
                var container = Container.open(tempContainerName);
                var signatureBytes = Convert.FromBase64String(signatureDto.Signature);
                var signature = container.signatures().First(); // Container must have one signature as it was added in PrepareContainer
                signature.setSignatureValue(signatureBytes);
                signature.extendSignatureProfile("BES/time-stamp");
                container.save();
            }
            finally
            {
                digidoc.terminate();
            }
        }

        private static string GetSupportedHashAlgorithm(IList<SignatureAlgorithmDto> supportedSignatureAlgorithms)
        {
            var algorithmNames = supportedSignatureAlgorithms.Select(a => a.HashFunction).ToArray();
            return algorithmNames switch
            {
                var a when a.Contains("SHA-384") => "SHA-384",
                var a when a.Contains("SHA-256") => "SHA-256",
                _ => throw new ArgumentException("SHA-384 or SHA-256 algorithm must be supported")
            };
        }
    }
}
