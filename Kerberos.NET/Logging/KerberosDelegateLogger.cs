// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using LogFunc = System.Action<
    System.Diagnostics.TraceLevel,
    string,
    int,
    object,
    object,
    System.Exception,
    string>;

namespace Kerberos.NET.Logging
{
    public class KerberosDelegateLogger : ILoggerFactory
    {
        private readonly LogFunc log;

        public KerberosDelegateLogger(LogFunc action)
        {
            this.log = action;
        }

        public void AddProvider(ILoggerProvider provider)
        {
        }

        public ILogger CreateLogger(string categoryName)
        {
            return new DelegateLogger(this.log, categoryName);
        }

        protected virtual void Dispose(bool disposing)
        {
        }

        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        private class DelegateLogger : ILogger, IDisposable
        {
            private readonly LogFunc log;
            private readonly string categoryName;

            private readonly ConcurrentStack<LoggerScope> scopes = new();

            private readonly LoggerScope defaultScope;

            private LoggerScope Scope
            {
                get
                {
                    if (this.scopes.TryPeek(out LoggerScope scope))
                    {
                        return scope;
                    }

                    return this.defaultScope;
                }
            }

            public DelegateLogger(LogFunc log, string categoryName)
            {
                this.log = log;
                this.categoryName = categoryName;

                this.defaultScope = new LoggerScope(null, log, categoryName, this.scopes);
            }

            public IDisposable BeginScope<TState>(TState state)
            {
                var scope = new LoggerScope(state, this.log, this.categoryName, this.scopes);

                this.scopes.Push(scope);

                return scope;
            }

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
            {
                this.Scope.Log(logLevel, eventId, state, exception, formatter);
            }

            public void Dispose()
            {
                this.defaultScope?.Dispose();
            }

            private class LoggerScope : IDisposable
            {
                private readonly object state;
                private readonly LogFunc log;
                private readonly string categoryName;
                private readonly ConcurrentStack<LoggerScope> scopes;

                public LoggerScope(object state, LogFunc log, string categoryName, ConcurrentStack<LoggerScope> scopes)
                {
                    this.state = state;
                    this.log = log;
                    this.categoryName = categoryName;
                    this.scopes = scopes;
                }

                public void Dispose()
                {
#pragma warning disable CA2000 // Dispose objects before losing scope
                    while (this.scopes.TryPop(out LoggerScope scope))
#pragma warning restore CA2000 // Dispose objects before losing scope
                    {
                        if (ReferenceEquals(scope, this))
                        {
                            break;
                        }
                    }
                }

                internal void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
                {
                    TraceLevel level = ConvertLogLevel(logLevel);

                    this.log(level, this.categoryName, eventId.Id, this.state, state, exception, formatter(state, exception));
                }

                private static TraceLevel ConvertLogLevel(LogLevel logLevel)
                {
                    return logLevel switch
                    {
                        LogLevel.Trace or LogLevel.Debug => TraceLevel.Verbose,
                        LogLevel.Information => TraceLevel.Info,
                        LogLevel.Warning => TraceLevel.Warning,
                        LogLevel.Error or LogLevel.Critical => TraceLevel.Error,
                        LogLevel.None => TraceLevel.Off,
                        _ => TraceLevel.Verbose,
                    };
                }
            }
        }
    }
}
