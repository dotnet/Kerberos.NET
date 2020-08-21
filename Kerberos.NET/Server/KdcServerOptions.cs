// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Net;
using System.Threading;
using Kerberos.NET.Entities;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET.Server
{
    /// <summary>
    /// The server parameters that dictate low-level behavior of each request
    /// </summary>
    public class KdcServerOptions
    {
        /// <summary>
        /// The IP and Port that the KDC should listen on if using a <see cref="KdcSocketWorker" />.
        /// </summary>
        public EndPoint ListeningOn { get; set; }

        /// <summary>
        /// The maximum number of TCP requests that should be queued before dropping incoming connections.
        /// </summary>
        public int QueueLength { get; set; } = 1000;

        /// <summary>
        /// The amount of time the KDC should wait receiving a request before timing out.
        /// </summary>
        public TimeSpan ReceiveTimeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// The amount of time the KDC should wait idle before receiving additional requests on the same connection.
        /// </summary>
        public TimeSpan AcceptTimeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// The global server cancellation token. This will trigger all threads to stop.
        /// </summary>
        public CancellationTokenSource Cancellation { get; set; }

        /// <summary>
        /// The maximum size of a request that will be accepted.
        /// </summary>
        public int MaxReadBufferSize { get; set; } = 1024 * 1024;

        /// <summary>
        /// The maximum size of a response that will be written.
        /// </summary>
        public int MaxWriteBufferSize { get; set; } = 64 * 1024;

        /// <summary>
        /// The log factory for the KDC and depedent components.
        /// </summary>
        public ILoggerFactory Log { get; set; }

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

        /// <summary>
        /// Indicates whether the KDC will parse [MS-KKDCP] messages.
        /// </summary>
        public bool ProxyEnabled { get; set; } = true;

        /// <summary>
        /// Indicates whether the KDC will automatically register an AS-REQ message handler.
        /// </summary>
        public bool RegisterDefaultAsReqHandler { get; set; } = true;

        /// <summary>
        /// Indicates whether the KDC will automatically register a TGS-REQ message handler.
        /// </summary>
        public bool RegisterDefaultTgsReqHandler { get; set; } = true;

        /// <summary>
        /// Indicates whether the KDC will automatically register the PKINIT pre-auth handler.
        /// </summary>
        public bool RegisterDefaultPkInitPreAuthHandler { get; set; } = true;
    }
}