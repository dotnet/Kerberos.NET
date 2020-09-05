// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Diagnostics;
using System.Linq;
using System.Text;
using Kerberos.NET;
using Kerberos.NET.Crypto;
using Microsoft.Extensions.Logging.Abstractions;

namespace Microsoft.Extensions.Logging
{
    internal static class LoggerExtensions
    {
        private static readonly Func<ILogger, Guid, IDisposable> BeginRequestScopeValue;
        private static readonly Action<ILogger, KerberosProtocolException> LogProtocolException;
        private static readonly Action<ILogger, string, Exception> LogBinaryTraceData;
        private static readonly Action<ILogger, string, Exception> LogKeyTabException;

#pragma warning disable CA1810 // Initialize reference type static fields inline
        static LoggerExtensions()
#pragma warning restore CA1810 // Initialize reference type static fields inline
        {
            BeginRequestScopeValue = LoggerMessage.DefineScope<Guid>("Request => {RequestScope}");
            LogProtocolException = LoggerMessage.Define(LogLevel.Warning, default, "Protocol failure");
            LogBinaryTraceData = LoggerMessage.Define<string>(LogLevel.Trace, default, "Traced binary data {Data}");
            LogKeyTabException = LoggerMessage.Define<string>(LogLevel.Warning, default, "{KeyTab}");
        }

        public static IDisposable BeginRequestScope(this ILogger logger, Guid scopeId)
        {
            Trace.CorrelationManager.ActivityId = scopeId;

            return BeginRequestScopeValue(logger, Trace.CorrelationManager.ActivityId);
        }

        public static void WarnCryptographicException(this ILogger logger, Exception ex, KeyTable keytab)
        {
            if (keytab == null)
            {
                return;
            }

            StringBuilder sb = new StringBuilder();

            sb.Append("Using keytab: [");

            foreach (var key in keytab.Entries.ToList())
            {
                sb.Append(key.ToString());
                sb.Append($" {key.Timestamp}; ");
            }

            if (keytab.Entries.Any())
            {
                sb.Remove(sb.Length - 1, 1);
            }

            sb.Append("]");

            LogKeyTabException(logger, sb.ToString(), ex);
        }

        public static void LogKerberosProtocolException(this ILogger logger, KerberosProtocolException pex)
        {
            LogProtocolException(logger, pex);
        }

        public static void TraceBinary(this ILogger logger, ReadOnlyMemory<byte> data)
        {
            if (logger.IsEnabled(LogLevel.Trace))
            {
                LogBinaryTraceData(logger, Environment.NewLine + data.ToArray().HexDump(), null);
            }
        }

        public static ILogger<T> CreateLoggerSafe<T>(this ILoggerFactory factory)
        {
            if (factory == null)
            {
                return NullLoggerFactory.Instance.CreateLogger<T>();
            }

            return factory.CreateLogger<T>();
        }
    }
}
