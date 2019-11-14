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

        public IDisposable Push() => Push(deferrals.Count == 0);

        private IDisposable Push(bool allocate)
        {
            if (allocate)
            {
                deferrals.Push(new Queue<Action>());

                return new DeferralStack(deferrals);
            }

            return null;
        }

        public void Defer(Action action)
        {
            deferrals.Peek().Enqueue(() =>
            {
                using (Push(true))
                {
                    action();
                }
            });
        }

        public void Dispose() => Pop();

        private void Pop()
        {
            var actions = deferrals.Pop();

            while (actions.Count > 0)
            {
                var action = actions.Dequeue();

                action();
            }
        }
    }
}
