using System.Windows.Forms;

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

        public override int ScoreForSession(Session oS)
        {
            if (oS.RequestHeaders["User-Agent"].OICStartsWith("kerberos/"))
            {
                return 100;
            }

            if ((401 == oS.responseCode && oS.ResponseHeaders["WWW-Authenticate"].OICStartsWith("N")) ||
                (407 == oS.responseCode && oS.ResponseHeaders["Proxy-Authenticate"].OICStartsWith("N")))
            {
                return 100;
            }

            TryDetectKdcProxy(oS, oS.ResponseBody);

            if (View.MessageParsed)
            {
                return 100;
            }

            if (oS.RequestHeaders["Authorization"].OICStartsWith("N"))
            {
                return 1;
            }

            if (oS.RequestHeaders["Authorization"].OICStartsWith("K"))
            {
                return 1;
            }

            return 0;
        }

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
