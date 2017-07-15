using Microsoft.Owin;
using Syfuhs.Security.Kerberos;
using Syfuhs.Security.Kerberos.Crypto;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

using NextFunc = System.Func<System.Collections.Generic.IDictionary<string, object>, System.Threading.Tasks.Task>;

namespace KerberosMiddlewareSample
{
    public class KerberosMiddleware
    {
        private readonly KerberosValidator validator;

        private readonly NextFunc next;

        public KerberosMiddleware(NextFunc next)
        {
            this.next = next;

            // NOTE: ValidateAfterDecrypt is a dangerous flag. It should only be used for samples

            validator = new KerberosValidator(new KerberosKey("P@ssw0rd!")) { ValidateAfterDecrypt = ValidationAction.None };
        }

        public async Task Invoke(IDictionary<string, object> environment)
        {
            var context = new OwinContext(environment);

            validator.Logger = context.TraceOutput.Write;

            ParseKerberosHeader(context);

            await next.Invoke(environment);
        }

        private void ParseKerberosHeader(OwinContext context)
        {
            string[] authzHeader = null;

            if (!context.Request.Headers.TryGetValue("Authorization", out authzHeader) || authzHeader.Length != 1)
            {
                return;
            }

            var header = authzHeader.First();

            var authenticator = new KerberosAuthenticator(validator);

            var identity = authenticator.Authenticate(header);

            context.Request.User = new ClaimsPrincipal(identity);
        }
    }
}
