namespace WebEid.AspNetCore.Example.Dto
{
    public class SignatureAlgorithmDto
    {
        public string CryptoAlgorithm { get; set; }
        public string HashFunction { get; set; }
        public string PaddingScheme { get; set; }
    }
}