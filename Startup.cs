using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.EntityFrameworkCore;
using Advanced.Models;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace Advanced
{
    public class Startup
    {
        public Startup(IConfiguration config) {
            Configuration = config;
        }

        public IConfiguration Configuration { get; set; }
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
             services.AddDbContext<DataContext>(opts=>{
                opts.UseMySql(Configuration["ConnectionStrings:DataAccessMySqlProvider"]);
                opts.EnableSensitiveDataLogging(true);
            });
            services.AddDbContext<IdentityContext>(opts=>{
                opts.UseMySql(Configuration["ConnectionStrings:IdentityConnection"]);
                
            });

            services.AddIdentity<IdentityUser,IdentityRole>()
                                .AddEntityFrameworkStores<IdentityContext>();
            
             services.AddControllersWithViews().AddRazorRuntimeCompilation();
            services.AddRazorPages().AddRazorRuntimeCompilation();
            services.AddServerSideBlazor();
             services.AddSingleton<Services.ToggleService>();

             services.Configure<IdentityOptions>(opts => {
                opts.Password.RequiredLength = 6;
                opts.Password.RequireNonAlphanumeric = false;
                opts.Password.RequireLowercase = false;
                opts.Password.RequireUppercase = false;
                opts.Password.RequireDigit = false;
                opts.User.RequireUniqueEmail = true;
                opts.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyz";
            });
            services.AddAuthentication(opts => {
                opts.DefaultScheme =
                    CookieAuthenticationDefaults.AuthenticationScheme;
                opts.DefaultChallengeScheme =
                    CookieAuthenticationDefaults.AuthenticationScheme;
            }).AddCookie(opts => {
                opts.Events.DisableRedirectForPath(e => e.OnRedirectToLogin,
                    "/api", StatusCodes.Status401Unauthorized);
                opts.Events.DisableRedirectForPath(e => e.OnRedirectToAccessDenied,
                    "/api", StatusCodes.Status403Forbidden);
            }).AddJwtBearer(opts => {
                opts.RequireHttpsMetadata = false;
                opts.SaveToken = true;
                opts.TokenValidationParameters = new TokenValidationParameters {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(
                        Encoding.ASCII.GetBytes(Configuration["jwtSecret"])),
                    ValidateAudience = false,
                    ValidateIssuer = false
                };
                opts.Events = new JwtBearerEvents {
                    OnTokenValidated = async ctx => {
                        var usrmgr = ctx.HttpContext.RequestServices
                            .GetRequiredService<UserManager<IdentityUser>>();
                        var signinmgr = ctx.HttpContext.RequestServices
                            .GetRequiredService<SignInManager<IdentityUser>>();
                        string username =
                            ctx.Principal.FindFirst(ClaimTypes.Name)?.Value;
                        IdentityUser idUser = await usrmgr.FindByNameAsync(username);
                        ctx.Principal =
                            await signinmgr.CreateUserPrincipalAsync(idUser);
                    }
                };
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, DataContext context)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            app.UseStaticFiles();
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
           app.UseEndpoints(endpoints => {
                endpoints.MapControllerRoute("controllers",
                    "controllers/{controller=Home}/{action=Index}/{id?}");
                endpoints.MapDefaultControllerRoute();
                endpoints.MapRazorPages();
                endpoints.MapBlazorHub();
                endpoints.MapFallbackToPage("/_Host");
            });

            SeedData.SeedDatabase(context);
            IdentitySeedData.CreateAdminAccount(app.ApplicationServices, Configuration);
        }
    }
}
