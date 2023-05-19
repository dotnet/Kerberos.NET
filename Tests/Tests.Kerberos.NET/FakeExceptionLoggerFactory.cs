// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace Tests.Kerberos.NET
{
    internal class FakeExceptionLoggerFactory : ILoggerFactory
    {
        private readonly ConcurrentBag<Exception> exceptions = new();
        private readonly ConcurrentBag<string> logs = new();

        public IEnumerable<Exception> Exceptions => this.exceptions;

        public IEnumerable<string> Logs => this.logs;

        public void AddProvider(ILoggerProvider provider)
        {
        }

        public ILogger CreateLogger(string categoryName)
        {
            return new ExceptionLogger(this.exceptions, this.logs);
        }

        public void Dispose()
        {
        }

        private class ExceptionLogger : ILogger
        {
            private readonly ConcurrentBag<Exception> exceptions;
            private readonly ConcurrentBag<string> logs;

            public ExceptionLogger(ConcurrentBag<Exception> exceptions, ConcurrentBag<string> logs)
            {
                this.exceptions = exceptions;
                this.logs = logs;
            }

            private class Scope : IDisposable
            {
                public void Dispose()
                {
                }
            }

            public IDisposable BeginScope<TState>(TState state)
            {
                return new Scope();
            }

            public bool IsEnabled(LogLevel logLevel)
            {
                return true;
            }

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
            {
                if (exception != null)
                {
                    this.exceptions.Add(exception);
                }

                this.logs.Add($"[{logLevel}] {eventId} " + formatter(state, exception));
            }
        }
    }
}