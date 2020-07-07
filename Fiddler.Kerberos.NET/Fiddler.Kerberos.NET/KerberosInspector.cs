using System;
using System.Linq;
using System.Windows.Forms;
using Kerberos.NET.Entities;

namespace Fiddler.Kerberos.NET
{
    public abstract class KerberosInspector : Inspector2
    {
        protected KerberosMessageView View { get; } = new KerberosMessageView();

        public override void AddToTab(TabPage o)
        {
            o.Text = "Kerberos";

            View.ResetLayout();

            o.Controls.Add(View);
        }

        public abstract void Inspect(Session session);

        public virtual void TryDetectKdcProxy(Session session, byte[] body)
        {
            View.ProcessMessage(body, "KDC Proxy");
        }

        public override void AssignSession(Session oS)
        {
            View.ResetLayout();

            Inspect(oS);

            base.AssignSession(oS);
        }

        public void Clear()
        {

        }

        public override int GetOrder()
        {
            return 10000;
        }

        public override InspectorFlags GetFlags()
        {
            return InspectorFlags.HideInAutoResponder;
        }
    }
}
