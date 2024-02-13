namespace WebEid.AspNetCore.Example.Services
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

    public class SigningService
    {
        private static readonly string FileToSign = Path.Combine("wwwroot", "files", "example-for-signing.txt");
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
                    container.prepareWebSignature(certificate.Export(X509ContentType.Cert), "time-stamp");
                var hashFunction = GetSupportedHashAlgorithm(data.SupportedSignatureAlgorithms, signature.signatureMethod());
                container.save();
                return new DigestDto
                {
                    Hash = Convert.ToBase64String(signature.dataToSign()),
                    HashFunction = hashFunction
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

        private static string GetSupportedHashAlgorithm(IList<SignatureAlgorithmDto> supportedSignatureAlgorithms, string signatureMethod)
        {
            var framgment = new Uri(signatureMethod).Fragment;
            if (supportedSignatureAlgorithms.FirstOrDefault(algo => FragmentEquals(framgment, algo), null) is SignatureAlgorithmDto algo)
            {
                return algo.HashFunction;
            }
            throw new ArgumentException("Supported signature algorithm not found");
        }

        private static bool FragmentEquals(string framgent, SignatureAlgorithmDto signatureAlgorithm) =>
            signatureAlgorithm switch
            {
                { CryptoAlgorithm: "ECC", PaddingScheme: "NONE", HashFunction: "SHA-224" } => framgent == "#ecdsa-sha224",
                { CryptoAlgorithm: "ECC", PaddingScheme: "NONE", HashFunction: "SHA-256" } => framgent == "#ecdsa-sha256",
                { CryptoAlgorithm: "ECC", PaddingScheme: "NONE", HashFunction: "SHA-384" } => framgent == "#ecdsa-sha384",
                { CryptoAlgorithm: "ECC", PaddingScheme: "NONE", HashFunction: "SHA-512" } => framgent == "#ecdsa-sha512",
                { CryptoAlgorithm: "RSA", PaddingScheme: "PKCS1.5", HashFunction: "SHA-224" } => framgent == "#rsa-sha224",
                { CryptoAlgorithm: "RSA", PaddingScheme: "PKCS1.5", HashFunction: "SHA-256" } => framgent == "#rsa-sha256",
                { CryptoAlgorithm: "RSA", PaddingScheme: "PKCS1.5", HashFunction: "SHA-384" } => framgent == "#rsa-sha384",
                { CryptoAlgorithm: "RSA", PaddingScheme: "PKCS1.5", HashFunction: "SHA-512" } => framgent == "#rsa-sha512",
                { CryptoAlgorithm: "RSA", PaddingScheme: "PSS", HashFunction: "SHA-224" } => framgent == "#sha224-rsa-MGF1",
                { CryptoAlgorithm: "RSA", PaddingScheme: "PSS", HashFunction: "SHA-256" } => framgent == "#sha256-rsa-MGF1",
                { CryptoAlgorithm: "RSA", PaddingScheme: "PSS", HashFunction: "SHA-384" } => framgent == "#sha384-rsa-MGF1",
                { CryptoAlgorithm: "RSA", PaddingScheme: "PSS", HashFunction: "SHA-512" } => framgent == "#sha512-rsa-MGF1",
                _ => false
            };
    }
}
