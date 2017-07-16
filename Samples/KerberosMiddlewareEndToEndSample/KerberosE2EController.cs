using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;

namespace KerberosMiddlewareEndToEndSample
{
    public class KerberosE2EController : ApiController
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