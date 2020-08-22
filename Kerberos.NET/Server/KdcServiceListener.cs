// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace Kerberos.NET.Server
{
    public class KdcServiceListener : ServiceListenerBase
    {
        public KdcServiceListener(KdcServerOptions options)
            : base(options, (socket, o) => new KdcSocketWorker(socket, o))
        {
        }
    }
}