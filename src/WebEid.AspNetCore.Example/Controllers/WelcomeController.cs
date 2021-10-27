namespace WebEid.AspNetCore.Example.Controllers
{
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;

    public class WelcomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
