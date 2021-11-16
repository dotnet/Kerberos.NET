// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Win32
{
    public class SspiContext : IDisposable
    {
        private readonly string spn;

        private readonly SspiSecurityContext context;
        private bool disposedValue;

        public SspiContext(string spn, string package = "Kerberos")
        {
            this.spn = spn;

            this.context = new SspiSecurityContext(Credential.Current(), package);
        }

        public byte[] SessionKey => this.context.QueryContextAttributeSession();

        public byte[] RequestToken(byte[] serverResponse = null)
        {
            var status = this.context.InitializeSecurityContext(this.spn, serverResponse, out byte[] clientRequest);

            if (status == ContextStatus.Error)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return clientRequest;
        }

        public void AcceptToken(byte[] token, out byte[] serverResponse)
        {
            var status = this.context.AcceptSecurityContext(token, out serverResponse);

            if (status == ContextStatus.Error)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!this.disposedValue)
            {
                if (disposing)
                {
                    this.context.Dispose();
                }

                this.disposedValue = true;
            }
        }

        public void Dispose()
        {
            this.Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
