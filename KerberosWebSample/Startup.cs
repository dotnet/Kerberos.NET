using Owin;
using System.Web.Http;

namespace KerberosWebSample
{
    public class Startup
    {
        public void Configuration(IAppBuilder appBuilder)
        {
            var config = new HttpConfiguration();

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );

            appBuilder.Use<KerberosEndToEndMiddleware>();

            appBuilder.UseWebApi(config);
        }
    }
}