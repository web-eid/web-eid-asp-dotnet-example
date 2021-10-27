namespace WebEid.AspNetCore.Example.Controllers.Api
{
    using System.Security;
    using System.Security.Claims;
    using Microsoft.AspNetCore.Mvc;

    public abstract class BaseController : ControllerBase
    {
        protected void RemoveUserContainerFile()
        {
            System.IO.File.Delete(GetUserContainerName());
        }

        protected string GetUserContainerName()
        {
            var identity = (ClaimsIdentity)this.HttpContext.User?.Identity ??
                           throw new SecurityException("User is not logged in");
            return identity.GetIdCode();
        }
    }
}
