namespace WebEid.AspNetCore.Example.Pages
{
    using System.Linq;
    using System.Security.Claims;
    using Microsoft.AspNetCore.Mvc.RazorPages;

    public class WelcomeModel : PageModel
    {
        public string PrincipalName => GetPrincipalName((ClaimsIdentity)this.User.Identity);

        private static string GetPrincipalName(ClaimsIdentity identity)
        {
            var givenName = identity.Claims.Where(claim => claim.Type == ClaimTypes.GivenName)
                .Select(claim => claim.Value)
                .SingleOrDefault();

            if (!string.IsNullOrEmpty(givenName))
            {
                var surname = identity.Claims.Where(claim => claim.Type == ClaimTypes.Surname)
                    .Select(claim => claim.Value)
                    .SingleOrDefault();
                return $"{givenName} {surname}";
            }
            else
            {
                // In case of organizations the Given Name and Surname are empty,
                // and we use Common Name instead.
                return identity.Claims.Where(claim => claim.Type == ClaimTypes.Name)
                    .Select(claim => claim.Value)
                    .SingleOrDefault();
            }
        }
    }
}
