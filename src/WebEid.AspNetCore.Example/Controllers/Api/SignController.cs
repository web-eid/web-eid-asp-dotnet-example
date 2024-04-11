namespace WebEid.AspNetCore.Example.Controllers.Api
{
    using System;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Logging;
    using Services;
    using WebEid.AspNetCore.Example.Dto;

    [Route("[controller]")]
    [ApiController]
    public class SignController : BaseController
    {
        private const string SignedFile = "example-for-signing.asice";
        private readonly SigningService signingService;
        private readonly ILogger logger;

        public SignController(SigningService signingService, ILogger logger)
        {
            this.signingService = signingService;
            this.logger = logger;
        }

        [Route("prepare")]
        [HttpPost]
        public DigestDto Prepare([FromBody] CertificateDto data)
        {
            return signingService.PrepareContainer(data, (ClaimsIdentity)HttpContext.User.Identity, GetUserContainerName());
        }

        [Route("sign")]
        [HttpPost]
        public FileDto Sign([FromBody] SignatureDto data)
        {
            signingService.SignContainer(data, GetUserContainerName());
            return new FileDto(SignedFile);
        }

        [Route("download")]
        [HttpGet]
        public async Task<IActionResult> Download()
        {
            try
            {
                var content = await System.IO.File.ReadAllBytesAsync(GetUserContainerName());
                return File(content, "application/vnd.etsi.asic-e+zip", SignedFile);
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Error occurred while downloading user container file");
                return BadRequest();
            }
        }
    }
}
