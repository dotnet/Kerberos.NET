// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Diagnostics;
using Kerberos.NET.Logging;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LogFunc = System.Action<
    System.Diagnostics.TraceLevel,
    string,
    int,
    object,
    object,
    System.Exception,
    string>;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class LogTests
    {
        [TestMethod]
        public void DelegateLogging()
        {
            using (KerberosDelegateLogger log = MakeLogger(new List<string>()))
            {
                Assert.IsNotNull(log);
            }
        }

        private static KerberosDelegateLogger MakeLogger(List<string> logLines)
        {
            LogFunc logger = (level, cateogry, id, scopeState, logState, exception, log) => LogImpl(level, cateogry, id, scopeState, logState, exception, log, logLines);

            return new KerberosDelegateLogger(logger);
        }

        [TestMethod]
        public void LogWrite()
        {
            var list = new List<string>();

            using (var log = MakeLogger(list))
            {
                var logger = log.CreateLogger("MyCategory");

                logger.LogInformation("message");
                logger.LogWarning("warning");
                logger.LogCritical("critical");
                logger.LogError("error");
                logger.LogDebug("debug");
                logger.LogTrace("trace");

                using (logger.BeginScope("state1"))
                {
                    logger.LogInformation("info scope 1");

                    using (logger.BeginScope("state2"))
                    {
                        logger.LogInformation("info scope 2");
                    }

                    logger.LogInformation("info scope 1 again");
                }

                logger.LogInformation("info again");
            }

            Assert.AreEqual(10, list.Count);

            Assert.AreEqual(list[0], "[Info] [MyCategory] 0  message  message");
            Assert.AreEqual(list[1], "[Warning] [MyCategory] 0  warning  warning");
            Assert.AreEqual(list[2], "[Error] [MyCategory] 0  critical  critical");
            Assert.AreEqual(list[3], "[Error] [MyCategory] 0  error  error");
            Assert.AreEqual(list[4], "[Verbose] [MyCategory] 0  debug  debug");
            Assert.AreEqual(list[5], "[Verbose] [MyCategory] 0  trace  trace");
            Assert.AreEqual(list[6], "[Info] [MyCategory] 0 state1 info scope 1  info scope 1");
            Assert.AreEqual(list[7], "[Info] [MyCategory] 0 state2 info scope 2  info scope 2");
            Assert.AreEqual(list[8], "[Info] [MyCategory] 0 state1 info scope 1 again  info scope 1 again");
            Assert.AreEqual(list[9], "[Info] [MyCategory] 0  info again  info again");
        }

        private static void LogImpl(
            TraceLevel level,
            string categoryName,
            int eventId,
            object scopeState,
            object logState,
            Exception exception,
            string log,
            List<string> logLines
        )
        {
            logLines.Add($"[{level}] [{categoryName}] {eventId} {scopeState} {logState} {exception} {log}");
        }
    }
}