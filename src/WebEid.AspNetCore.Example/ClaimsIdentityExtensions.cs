namespace WebEid.AspNetCore.Example
{
    using System.Linq;
    using System.Security.Claims;

    public static class ClaimsIdentityExtensions
    {
        public static string GetIdCode(this ClaimsIdentity identity)
        {
            return identity.Claims.SingleOrDefault(claim => claim.Type == ClaimTypes.NameIdentifier)?.Value;
        }
    }
}
