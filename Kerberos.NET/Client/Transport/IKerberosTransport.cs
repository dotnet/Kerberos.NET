// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Asn1;
using Kerberos.NET.Configuration;
using Kerberos.NET.Entities.ChangePassword;

namespace Kerberos.NET.Transport
{
    public interface IKerberosTransport
    {
        bool TransportFailed { get; set; }

        KerberosTransportException LastError { get; set; }

        bool Enabled { get; set; }

        TimeSpan ConnectTimeout { get; set; }

        TimeSpan SendTimeout { get; set; }

        TimeSpan ReceiveTimeout { get; set; }

        int MaximumAttempts { get; set; }

        Krb5Config Configuration { get; set; }

        Task<TResponse> SendMessage<TRequest, TResponse>(
            string domain,
            IAsn1ApplicationEncoder<TRequest> req,
            CancellationToken cancellation = default
        )
            where TResponse : IAsn1ApplicationEncoder<TResponse>, new();

        Task<T> SendMessage<T>(
            string domain,
            ReadOnlyMemory<byte> req,
            CancellationToken cancellation = default
        )
            where T : IAsn1ApplicationEncoder<T>, new();
    }

    public interface IKerberosTransport2: IKerberosTransport
    {
        Task<ReadOnlyMemory<byte>> SendMessage(
            string domain,
            ReadOnlyMemory<byte> req,
            CancellationToken cancellation = default
        );

        Task<KrbChangePasswdRep> SendMessageChangePassword(
            string domain,
            KrbChangePasswdReq msg,
            CancellationToken cancellation = default
        );

        Task<ReadOnlyMemory<byte>> SendMessageChangePassword(
            string domain,
            ReadOnlyMemory<byte> req,
            CancellationToken cancellation = default
        );
    }
}
