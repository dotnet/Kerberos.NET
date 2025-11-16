// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

internal static class TaskExtensions
{
    public static async Task<TResult> GetFastestAsync<TSource, TResult>(this IEnumerable<TSource> source, Func<TSource, CancellationToken, Task<TResult>> task, CancellationToken cancellationToken = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var tasks = new HashSet<Task<TResult>>(source.Select(e => task(e, cts.Token)));
        if (tasks.Count == 0)
        {
            return default;
        }

        var exceptions = new List<Exception>();
        do
        {
            var completedTask = await Task.WhenAny(tasks);
            if (completedTask.Status == TaskStatus.RanToCompletion)
            {
                cts.Cancel();
                return completedTask.Result;
            }

            if (completedTask.Exception != null)
            {
                exceptions.AddRange(completedTask.Exception.InnerExceptions);
            }
            tasks.Remove(completedTask);
        } while (tasks.Count > 0);

        throw new AggregateException(exceptions);
    }
}
