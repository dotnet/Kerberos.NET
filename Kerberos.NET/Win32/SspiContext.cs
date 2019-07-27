using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Win32
{
    public class SspiContext : IDisposable
    {
        private readonly string spn;

        private readonly SspiSecurityContext context;

        public SspiContext(string spn, string package = "Kerberos")
        {
            this.spn = spn;

            context = new SspiSecurityContext(Credential.Current(), package);
        }

        public void Dispose()
        {
            context.Dispose();
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

        public void AcceptToken(byte[] token, out byte[] serverResponse)
        {
            var status = context.AcceptSecurityContext(token, out serverResponse);

            if (status == ContextStatus.Error)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
    }
}
