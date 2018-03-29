using Kerberos.NET;
using Kerberos.NET.Crypto;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System;
using System.ComponentModel;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace KerbDump
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            this.AutoScaleDimensions = new System.Drawing.SizeF(96F, 96F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Dpi;

            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            try
            {
                Decode().Wait();
            }
            catch (Exception ex)
            {
                ShowError(ex);
            }
        }

        private async Task Decode()
        {
            string ticket;

            if (string.IsNullOrWhiteSpace(txtKey.Text))
            {
                ticket = Decode(txtTicket.Text);
            }
            else
            {
                KeyTable key;

                if (chkEncodedKey.Checked)
                {
                    var bytes = Convert.FromBase64String(txtKey.Text);

                    key = new KeyTable(new KerberosKey(password: bytes, host: txtHost.Text));
                }
                else
                {
                    key = new KeyTable(new KerberosKey(txtKey.Text, host: string.IsNullOrWhiteSpace(txtHost.Text) ? null : txtHost.Text));
                }

                ticket = await Decode(txtTicket.Text, key);
            }

            txtDump.Text = ticket;

            CreateTreeView(txtDump.Text);
        }

        private async Task<string> Decode(string ticket, KeyTable key)
        {
            var validator = new KerberosValidator(key) { ValidateAfterDecrypt = ValidationActions.None };

            var ticketBytes = Convert.FromBase64String(ticket);

            var decrypted = await validator.Validate(ticketBytes);

            var request = KerberosRequest.Parse(ticketBytes);

            return FormatSerialize(new { Request = request, Decrypted = decrypted });
        }

        private string FormatSerialize(object obj)
        {
            var settings = new JsonSerializerSettings
            {
                Formatting = Formatting.Indented,
                Converters = new[] { new StringEnumConverter() },
                ContractResolver = new KerberosIgnoreResolver()
            };

            return JsonConvert.SerializeObject(obj, settings);
        }

        private string Decode(string ticket)
        {
            var ticketBytes = Convert.FromBase64String(ticket);

            KerberosRequest request = KerberosRequest.Parse(ticketBytes);

            return FormatSerialize(request);
        }

        private void btnDecodeLocal_Click(object sender, EventArgs e)
        {
            try
            {
                RequestLocalTicket();

                txtHost.Text = Environment.MachineName.ToLowerInvariant();

                using (var secret = new LSASecret("$MACHINE.ACC"))
                {
                    secret.GetSecret(out byte[] bytes);

                    txtKey.Text = Convert.ToBase64String(bytes);
                }

                chkEncodedKey.Checked = true;

                button1_Click(sender, e);
            }
            catch (Exception ex)
            {
                ShowError(ex);
            }
        }

        private void ShowError(Exception ex)
        {
            treeView1.Nodes.Clear();

            var sb = new StringBuilder();

            if (ex is AggregateException agg)
            {
                foreach (var aggEx in agg.InnerExceptions)
                {
                    sb.AppendFormat("{0}\r\n\r\n", aggEx);
                }
            }
            else
            {
                sb.Append(ex.ToString());
            }

            txtDump.Text = sb.ToString();
        }

        private void RequestLocalTicket()
        {
            var tokenProvider = new KerberosSecurityTokenProvider(
                Environment.MachineName,
                TokenImpersonationLevel.Identification
            );

            var securityToken = tokenProvider.GetToken(TimeSpan.FromMinutes(1)) as KerberosRequestorSecurityToken;

            txtTicket.Text = Convert.ToBase64String(securityToken.GetRequest());
        }

        private void CreateTreeView(string json)
        {
            treeView1.BeginUpdate();

            treeView1.Nodes.Clear();

            using (var reader = new StringReader(json))
            using (var jsonReader = new JsonTextReader(reader))
            {
                var obj = JToken.Load(jsonReader);

                var root = new TreeNode("Decoded Ticket");

                AddNode(obj, root);

                treeView1.Nodes.Add(root);

                treeView1.ExpandAll();
            }

            if (treeView1.Nodes.Count > 0)
            {
                treeView1.Nodes[0].EnsureVisible();
            }

            treeView1.EndUpdate();
        }

        private void AddNode(JToken token, TreeNode inTreeNode)
        {
            if (token == null)
            {
                return;
            }

            if (token is JValue)
            {
                inTreeNode.Nodes.Add(new TreeNode(token.ToString()));
            }
            else if (token is JObject obj)
            {
                foreach (var property in obj.Properties())
                {
                    var childNode = new TreeNode(property.Name);

                    AddNode(property.Value, childNode);

                    inTreeNode.Nodes.Add(childNode);
                }
            }
            else if (token is JArray array)
            {
                for (int i = 0; i < array.Count; i++)
                {
                    var childNode = inTreeNode.Nodes[inTreeNode.Nodes.Add(new TreeNode(i.ToString()))];

                    AddNode(array[i], childNode);
                }
            }
        }
    }

    public class LSASecret : IDisposable
    {
        private const string ADVAPI32 = "advapi32.dll";
        private const uint POLICY_GET_PRIVATE_INFORMATION = 0x00000004;

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public LSA_UNICODE_STRING ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [DllImport(ADVAPI32, SetLastError = true, PreserveSig = true)]
        private static extern uint LsaRetrievePrivateData(
            IntPtr PolicyHandle,
            ref LSA_UNICODE_STRING KeyName,
            out IntPtr PrivateData
        );

        [DllImport(ADVAPI32, SetLastError = true, PreserveSig = true)]
        private static extern uint LsaOpenPolicy(
           ref LSA_UNICODE_STRING SystemName,
           ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
           uint DesiredAccess,
           out IntPtr PolicyHandle
        );

        [DllImport(ADVAPI32, SetLastError = true, PreserveSig = true)]
        private static extern int LsaNtStatusToWinError(uint status);

        [DllImport(ADVAPI32, SetLastError = true, PreserveSig = true)]
        private static extern uint LsaClose(IntPtr policyHandle);

        [DllImport(ADVAPI32, SetLastError = true, PreserveSig = true)]
        private static extern uint LsaFreeMemory(IntPtr buffer);

        private LSA_UNICODE_STRING secretName;

        private readonly IntPtr lsaPolicyHandle;

        public LSASecret(string key)
        {
            secretName = new LSA_UNICODE_STRING()
            {
                Buffer = Marshal.StringToHGlobalUni(key),
                Length = (ushort)(key.Length * 2),
                MaximumLength = (ushort)((key.Length + 1) * 2)
            };

            var localsystem = default(LSA_UNICODE_STRING);
            var objectAttributes = default(LSA_OBJECT_ATTRIBUTES);

            var winErrorCode = LsaNtStatusToWinError(
                LsaOpenPolicy(
                    ref localsystem,
                    ref objectAttributes,
                    POLICY_GET_PRIVATE_INFORMATION,
                    out lsaPolicyHandle
                )
            );

            if (winErrorCode != 0)
            {
                throw new Win32Exception(winErrorCode);
            }
        }

        private static void FreeMemory(IntPtr Buffer)
        {
            var winErrorCode = LsaNtStatusToWinError(LsaFreeMemory(Buffer));

            if (winErrorCode != 0)
            {
                throw new Win32Exception(winErrorCode);
            }
        }

        public string GetSecret(out byte[] data)
        {
            var privateData = IntPtr.Zero;

            var winErrorCode = LsaNtStatusToWinError(
                LsaRetrievePrivateData(lsaPolicyHandle, ref secretName, out privateData)
            );

            if (winErrorCode != 0)
            {
                throw new Win32Exception(winErrorCode);
            }

            var lusSecretData = (LSA_UNICODE_STRING)Marshal.PtrToStructure(privateData, typeof(LSA_UNICODE_STRING));

            data = new byte[lusSecretData.Length];

            Marshal.Copy(lusSecretData.Buffer, data, 0, lusSecretData.Length);

            FreeMemory(privateData);

            return Encoding.Unicode.GetString(data);
        }

        public void Dispose()
        {
            var winErrorCode = LsaNtStatusToWinError(LsaClose(lsaPolicyHandle));

            if (winErrorCode != 0)
            {
                throw new Win32Exception(winErrorCode);
            }
        }
    }
}
