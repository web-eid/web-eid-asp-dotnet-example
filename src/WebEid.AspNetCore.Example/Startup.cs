namespace WebEid.AspNetCore.Example
{
    using Certificates;
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore.HttpOverrides;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Hosting;
    using Microsoft.Extensions.Logging;
    using Services;
    using System;
    using System.Security.Cryptography;
    using Security.Challenge;
    using Security.Validator;
    using System.Configuration;
    using Microsoft.AspNetCore.Authorization;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;

    public class Startup
    {
        public Startup(IConfiguration configuration, IWebHostEnvironment environment)
        {
            Configuration = configuration;
            CurrentEnvironment = environment;
        }

        private IConfiguration Configuration { get; }
        private IWebHostEnvironment CurrentEnvironment { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
            });
            var logger = loggerFactory.CreateLogger("Web-eId ASP.NET Core Example");
            services.AddSingleton(logger);

            services.AddRazorPages(options =>
            {
                options.Conventions.AuthorizePage("/welcome", "LoggedInOnly");
            });

            services.AddAuthorization(options =>
            {
                options.AddPolicy("LoggedInOnly", policy =>
                {
                    policy.AuthenticationSchemes.Add(CookieAuthenticationDefaults.AuthenticationScheme);
                    policy.RequireAuthenticatedUser();
                    policy.Requirements.Add(new LoggedInRequirement());
                });
            });

            services.AddSingleton<IAuthorizationHandler, LoggedInAuthorizationHandler>();

            services.AddControllers();
            services.AddMvc(options =>
            {
                options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
            });

            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
                {
                    options.Cookie.Name = "WebEid.AspNeCore.Example.Auth";
                    options.Cookie.SameSite = SameSiteMode.Strict;
                    options.Events.OnRedirectToLogin = context =>
                    {
                        context.Response.Redirect("/");
                        return Task.CompletedTask;
                    };
                    options.Events.OnRedirectToAccessDenied = context =>
                    {
                        context.Response.Redirect("/");
                        return Task.CompletedTask;
                    };
                });

            services.AddSession(options =>
            {
                options.Cookie.Name = "WebEid.AspNetCore.Example.Session";
                options.IdleTimeout = TimeSpan.FromSeconds(60);
                options.Cookie.IsEssential = true;
            });

            var url = GetOriginUrl(Configuration);

            services.AddSingleton(new AuthTokenValidatorBuilder(logger)
                .WithSiteOrigin(url)
                .WithTrustedCertificateAuthorities(CertificateLoader.LoadTrustedCaCertificatesFromDisk(CurrentEnvironment.IsDevelopment()))
                .Build());

            services.AddSingleton(RandomNumberGenerator.Create());
            services.AddSingleton<SigningService>();
            services.AddSingleton<DigiDocConfiguration>();
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            services.AddSingleton<IChallengeNonceStore, SessionBackedChallengeNonceStore>();
            services.AddSingleton<IChallengeNonceGenerator, ChallengeNonceGenerator>();

            services.AddAntiforgery();

            // Add support for running behind a TLS terminating proxy.
            services.Configure<ForwardedHeadersOptions>(options =>
            {
                options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
                // Only use this if you're behind a known proxy:
                options.KnownNetworks.Clear();
                options.KnownProxies.Clear();
            });
        }

        private static Uri GetOriginUrl(IConfiguration configuration)
        {
            var url = configuration["OriginUrl"];
            if (string.IsNullOrWhiteSpace(url))
            {
                throw new ConfigurationErrorsException("OriginUrl is not configured");
            }

            return new Uri(url);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseHttpsRedirection();
            }
            else
            {
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
                // Add support for running behind a TLS terminating proxy.
                app.UseForwardedHeaders();
            }

            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthorization();
            app.UseAuthentication();
            app.UseSession();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapRazorPages();
                endpoints.MapControllers();
            });
        }
    }
}
