// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Threading;
using Kerberos.NET.Configuration;
using Kerberos.NET.Entities;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET.Server
{
    /// <summary>
    /// The server parameters that dictate low-level behavior of each request
    /// </summary>
    public class KdcServerOptions
    {
        private Krb5Config config;

        /// <summary>
        /// The configuration that dictates how the KDC will operate.
        /// </summary>
        public Krb5Config Configuration
        {
            get => this.config ??= Krb5Config.Kdc();
            set => this.config = value;
        }

        /// <summary>
        /// The log factory for the KDC and depedent components.
        /// </summary>
        public ILoggerFactory Log { get; set; }

        /// <summary>
        /// The global server cancellation token. This will trigger all threads to stop.
        /// </summary>
        public CancellationTokenSource Cancellation { get; set; }

        /// <summary>
        /// The realm that will be used if a realm name is required before the pipeline has processed a message.
        /// </summary>
        public string DefaultRealm { get; set; }

        /// <summary>
        /// Indicates whether the server should emit debug logs or enable debugger features.
        /// </summary>
        public bool IsDebug { get; set; }

        /// <summary>
        /// The function that translates an incoming realm to that realms <see cref="IRealmService" />
        /// </summary>
        public Func<string, IRealmService> RealmLocator { get; set; }

        /// <summary>
        /// The function that generates the next logged transaction Id for each request.
        /// </summary>
        public Func<Guid> NextScopeId { get; set; } = KerberosConstants.GetRequestActivityId;
    }
}
