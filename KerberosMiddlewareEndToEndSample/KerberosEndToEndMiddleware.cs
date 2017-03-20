using Microsoft.Owin;
using Syfuhs.Security.Kerberos;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using NextFunc = System.Func<System.Collections.Generic.IDictionary<string, object>, System.Threading.Tasks.Task>;

namespace KerberosMiddlewareEndToEndSample
{
    internal class KerberosEndToEndMiddleware
    {
        private readonly SimpleKerberosValidator validator;

        private readonly NextFunc next;

        public KerberosEndToEndMiddleware(NextFunc next)
        {
            this.next = next;

            // NOTE: ValidateAfterDecrypt is a dangerous flag. It should only be used for samples

            validator = new SimpleKerberosValidator("P@ssw0rd!") { ValidateAfterDecrypt = false };
        }

        public async Task Invoke(IDictionary<string, object> environment)
        {
            var context = new OwinContext(environment);

            validator.Logger = context.TraceOutput.Write;

            if (ParseKerberosHeader(context))
            {
                await next.Invoke(environment);
            }
        }

        private bool ParseKerberosHeader(OwinContext context)
        {
            string[] authzHeader = null;

            if (!context.Request.Headers.TryGetValue("Authorization", out authzHeader) || authzHeader.Length != 1)
            {
                context.Response.Headers.Add("WWW-Authenticate", new[] { "Negotiate" });
                context.Response.StatusCode = 401;

                return false;
            }

            var header = authzHeader.First();

            try
            {
                var identity = validator.Validate(header);

                context.Request.User = new ClaimsPrincipal(identity);

                return true;
            }
            catch (Exception ex) {
                context.TraceOutput.WriteLine(ex);

                return false;
            }
        }
    }
}