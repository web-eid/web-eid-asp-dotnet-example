namespace WebEid.AspNetCore.Example.Certificates
{
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;

    internal static class CertificateLoader
    {
        public static X509Certificate2[] LoadTrustedCaCertificatesFromDisk(bool isTest = false)
        {
            return new FileReader(GetCertPath(isTest), "*.cer").ReadFiles()
                .Select(file => new X509Certificate2(file))
                .ToArray();
        }

        private static string GetCertPath(bool isTest)
        {
            return isTest ? "Certificates/Dev" : "Certificates/Prod";
        }
    }

    internal class FileReader
    {
        private readonly string path;
        private readonly string searchPattern;

        public FileReader(string path, string searchPattern = null)
        {
            this.path = path;
            this.searchPattern = searchPattern;
        }

        public IEnumerable<byte[]> ReadFiles()
        {
            foreach (var file in Directory.EnumerateFiles(this.path, this.searchPattern))
            {
                yield return File.ReadAllBytes(file);
            }
        }
    }
}
