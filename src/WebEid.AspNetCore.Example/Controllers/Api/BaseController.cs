namespace WebEid.AspNetCore.Example.Controllers.Api
{
    using System;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;

    public abstract class BaseController : ControllerBase
    {
        const string uniqueIdKey = "UniqueId";

        protected void RemoveUserContainerFile()
        {
            System.IO.File.Delete(GetUserContainerName());
        }

        protected void SetUniqueIdInSession() 
        {
            HttpContext.Session.SetString(uniqueIdKey, Guid.NewGuid().ToString());
        }

        private string GetUniqueIdFromSession() 
        {
            return HttpContext.Session.GetString(uniqueIdKey);
        }

        protected string GetUserContainerName()
        {
            return $"container_{GetUniqueIdFromSession()}";
        }
    }
}
