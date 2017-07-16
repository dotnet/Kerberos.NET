using Newtonsoft.Json;
using System.Linq;
using System.Security.Claims;
using System.Web.Http;

namespace KerberosWebSample
{
    public class KerberosController : ApiController
    {
        private static readonly JsonSerializerSettings Settings = new JsonSerializerSettings
        {
            Formatting = Formatting.Indented
        };

        public IHttpActionResult Get()
        {
            var claimsIdentity = User.Identity as ClaimsIdentity;

            var claims = claimsIdentity.Claims.Select(c => new { c.Value, c.Type });

            return Json(
                new
                {
                    claimsIdentity.Name,
                    claimsIdentity.IsAuthenticated,
                    claims
                },
                Settings
            );
        }
    }
}