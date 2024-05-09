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

﻿namespace WebEid.AspNetCore.Example.Certificates
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
