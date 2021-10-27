namespace WebEid.AspNetCore.Example
{
    using Microsoft.AspNetCore.Authorization;
    using System.Threading.Tasks;

    public class LoggedInAuthorizationHandler : AuthorizationHandler<LoggedInRequirement>
    {
        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context, LoggedInRequirement requirement)
        {
            if (context.User.Identity.IsAuthenticated)
            {
                context.Succeed(requirement);
            }
            return Task.CompletedTask;
        }
    }

    public class LoggedInRequirement : IAuthorizationRequirement { }

}
