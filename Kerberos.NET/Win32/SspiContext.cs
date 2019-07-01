using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Win32
{
    public class SspiContext
    {
        private readonly string spn;

        private readonly SspiSecurityContext context;

        public SspiContext(string spn)
        {
            this.spn = spn;

            context = new SspiSecurityContext(Credential.Current(), "Kerberos");
        }

        public byte[] RequestToken()
        {
            var status = context.InitializeSecurityContext(spn, null, out byte[] clientRequest);

            if (status == ContextStatus.Error)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return clientRequest;
        }
    }
}
