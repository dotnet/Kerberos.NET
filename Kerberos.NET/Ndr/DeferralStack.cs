// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Kerberos.NET.Ndr
{
    [DebuggerDisplay("Count = {deferrals.Count}")]
    internal class DeferralStack : IDisposable
    {
        private readonly Stack<Queue<Action>> deferrals;

        public DeferralStack(Stack<Queue<Action>> deferrals = null)
        {
            this.deferrals = deferrals ?? new Stack<Queue<Action>>();
        }

        public IDisposable Push() => this.Push(this.deferrals.Count == 0);

        private IDisposable Push(bool allocate)
        {
            if (allocate)
            {
                this.deferrals.Push(new Queue<Action>());

                return new DeferralStack(this.deferrals);
            }

            return null;
        }

        public void Defer(Action action)
        {
            this.deferrals.Peek().Enqueue(() =>
            {
                using (this.Push(true))
                {
                    action();
                }
            });
        }

        public void Dispose() => this.Pop();

        private void Pop()
        {
            if (this.deferrals.Count <= 0)
            {
                return;
            }

            var actions = this.deferrals.Pop();

            while (actions.Count > 0)
            {
                var action = actions.Dequeue();

                action();
            }
        }
    }
}