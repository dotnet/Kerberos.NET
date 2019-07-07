using KerbDump.Properties;
using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Win32;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

#pragma warning disable IDE1006 // Naming Styles

namespace KerbDump
{
    public partial class Form1 : Form
    {
        private const string RequestTemplateText = "Request for {0}";

        public Form1()
        {
            this.AutoScaleDimensions = new System.Drawing.SizeF(96F, 96F);
            this.AutoScaleMode = AutoScaleMode.Dpi;

            InitializeComponent();

            CryptographyService.RegisterCryptographicAlgorithm(EncryptionType.NULL, () => new NoopTransform());

            SetHost();

            txtHost.TextChanged += Host_Changed;

            txtHost.Text = hostName;

            TryLoadPersistedSettings();
        }

        private void TryLoadPersistedSettings()
        {
            if (!Settings.Default.ShouldRemember)
            {
                chkRemember.Checked = false;

                return;
            }

            txtTicket.Text = Settings.Default.Ticket;
            txtKey.Text = Unprotect(Settings.Default.Secret);
            chkEncodedKey.Checked = Settings.Default.IsSecretEncoded;
            txtHost.Text = Settings.Default.Host;

            button1_Click(this, EventArgs.Empty);
        }

        private void SetHost()
        {
            hostName = Environment.MachineName.ToLowerInvariant();
        }

        string hostName = "";

        private void Host_Changed(object sender, EventArgs e)
        {
            hostName = txtHost.Text;

            if (!string.IsNullOrWhiteSpace(hostName))
            {
                btnRequest.Text = string.Format(RequestTemplateText, hostName);
            }
            else
            {
                btnRequest.Text = string.Format(RequestTemplateText, "<host>");
            }
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
            if (chkRemember.Checked)
            {
                TryPersistingValues();
            }
            else
            {
                ResetPersistedValues();
            }

            if (string.IsNullOrWhiteSpace(txtTicket.Text))
            {
                return;
            }

            string ticket;

            if (string.IsNullOrWhiteSpace(txtKey.Text))
            {
                ticket = Decode(txtTicket.Text);
            }
            else
            {
                var key = table;

                var domain = Environment.GetEnvironmentVariable("USERDNSDOMAIN");

                if (key == null)
                {
                    if (chkEncodedKey.Checked)
                    {
                        var bytes = Convert.FromBase64String(txtKey.Text);

                        key = new KeyTable(
                            new KerberosKey(
                                password: bytes,
                                principal: new PrincipalName(PrincipalNameType.NT_SRV_HST, domain, new[] { Environment.MachineName }),
                                host: txtHost.Text
                            )
                        );
                    }
                    else
                    {
                        key = new KeyTable(
                            new KerberosKey(
                                txtKey.Text,
                                principalName: new PrincipalName(PrincipalNameType.NT_SRV_HST, domain, new[] { Environment.MachineName }),
                                host: string.IsNullOrWhiteSpace(txtHost.Text) ? null : txtHost.Text
                            )
                        );
                    }
                }

                ticket = await Decode(txtTicket.Text, key);
            }

            DisplayDeconstructed(ticket, "Decoded Ticket");
        }

        private void ResetPersistedValues()
        {
            try
            {
                Settings.Default.Reset();
                Settings.Default.Save();
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
            }
        }

        private void TryPersistingValues()
        {
            try
            {
                Settings.Default.ShouldRemember = true;

                Settings.Default.Ticket = txtTicket.Text;
                Settings.Default.Secret = Protect(txtKey.Text);
                Settings.Default.IsSecretEncoded = chkEncodedKey.Checked;
                Settings.Default.Host = txtHost.Text;

                Settings.Default.Save();
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
            }
        }

        private string Protect(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                return text;
            }

            var protectedSecret = ProtectedData.Protect(Encoding.Unicode.GetBytes(text), null, DataProtectionScope.CurrentUser);

            return Convert.ToBase64String(protectedSecret);
        }

        private string Unprotect(string secret)
        {
            if (string.IsNullOrWhiteSpace(secret))
            {
                return secret;
            }

            var unprotected = ProtectedData.Unprotect(Convert.FromBase64String(secret), null, DataProtectionScope.CurrentUser);

            return Encoding.Unicode.GetString(unprotected);
        }

        private void DisplayDeconstructed(string ticket, string label)
        {
            label2.Text = label;

            txtDump.Text = ticket;

            CreateTreeView(ticket, label);
        }

        private async Task<string> Decode(string ticket, KeyTable key)
        {
            ticket = StripWhitespace(ticket);

            var validator = new KerberosValidator(key) { ValidateAfterDecrypt = ValidationActions.Pac };

            validator.Logger.Enabled = false;

            var ticketBytes = Convert.FromBase64String(ticket);

            var decrypted = await validator.Validate(ticketBytes);

            var request = MessageParser.Parse(ticketBytes);

            var keytableFormat = GenerateFormattedKeyTable(key);

            var authenticated = await new KerberosAuthenticator(validator).Authenticate(ticketBytes) as KerberosIdentity;

            return FormatSerialize(new
            {
                Request = request,
                Decrypted = decrypted,
                Identity = new
                {
                    authenticated.Name,
                    authenticated.Restrictions,
                    authenticated.ValidationMode,
                    Claims = authenticated.Claims.Select(c => new { c.Type, c.Value })
                },
                KeyTable = keytableFormat
            });
        }

        private static string StripWhitespace(string ticket)
        {
            return ticket.Replace("\r", "").Replace("\n", "").Replace("\t", "").Replace(" ", "");
        }

        private object GenerateFormattedKeyTable(KeyTable keytab)
        {
            if (keytab == null)
            {
                return null;
            }

            var keys = keytab.Entries.Select(k =>
            {
                var key = new KerberosKey(
                    Encoding.Unicode.GetString(
                        k.Key.GetKey(
                            CryptographyService.CreateTransform(EncryptionType.NULL)
                        )
                    ),
                    k.Principal
                );

                return new
                {
                    k.EncryptionType,
                    k.Length,
                    k.Timestamp,
                    k.Version,
                    key.Host,
                    key.PasswordBytes,
                    KeyPrincipalName = key.PrincipalName,
                    key.Salt
                };
            });

            var table = new
            {
                keytab.FileVersion,
                keytab.KerberosVersion,
                Entries = keys.ToArray()
            };

            return table;
        }

        private string FormatSerialize(object obj)
        {
            var settings = new JsonSerializerSettings
            {
                Formatting = Formatting.Indented,
                Converters = new[] { new StringEnumArrayConverter() },
                ContractResolver = new KerberosIgnoreResolver()
            };

            return JsonConvert.SerializeObject(obj, settings);
        }

        private class StringEnumArrayConverter : StringEnumConverter
        {
            public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
            {
                if (value == null)
                {
                    writer.WriteNull();
                    return;
                }

                Enum e = (Enum)value;

                var enumVal = e.ToString().Split(new[] { ", " }, StringSplitOptions.RemoveEmptyEntries);

                writer.WriteStartArray();

                foreach (var en in enumVal)
                {
                    writer.WriteValue(en);
                }

                writer.WriteEndArray();
            }
        }

        private string Decode(string ticket)
        {
            ticket = StripWhitespace(ticket);

            var ticketBytes = Convert.FromBase64String(ticket);

            var request = MessageParser.Parse(ticketBytes);

            var keytab = GenerateFormattedKeyTable(table);

            var obj = new { Request = request, KeyTable = keytab };

            return FormatSerialize(obj);
        }

        private void btnDecodeLocal_Click(object sender, EventArgs e)
        {
            try
            {
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
            if (string.IsNullOrWhiteSpace(hostName))
            {
                SetHost();

                txtHost.Text = hostName;
            }

            SspiContext context = new SspiContext(spn: hostName);

            byte[] tokenBytes = context.RequestToken();

            txtTicket.Text = Convert.ToBase64String(tokenBytes);
        }

        private void CreateTreeView(string json, string label)
        {
            treeView1.BeginUpdate();

            treeView1.Nodes.Clear();

            using (var reader = new StringReader(json))
            using (var jsonReader = new JsonTextReader(reader))
            {
                var obj = JToken.Load(jsonReader);

                var root = new TreeNode(label);

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
                    var value = array[i];

                    if (value.Type == JTokenType.String)
                    {
                        AddNode(value, inTreeNode);
                    }
                    else
                    {
                        var typeNames = new[] { "Type", "Mechanism", "Value" };

                        string typeName = null;

                        foreach (var type in typeNames)
                        {
                            if (TryExtractPropertyForName(value, type, out typeName))
                            {
                                break;
                            }
                        }

                        if (string.IsNullOrWhiteSpace(typeName))
                        {
                            typeName = i.ToString();
                        }

                        var childNode = inTreeNode.Nodes[inTreeNode.Nodes.Add(new TreeNode(typeName))];

                        AddNode(value, childNode);
                    }
                }
            }
        }

        private static bool TryExtractPropertyForName(JToken value, string type, out string typeName)
        {
            typeName = null;

            if (value is JObject valueObj &&
                valueObj.TryGetValue(type, out JToken typeProp))
            {
                typeName = typeProp.ToString();

                valueObj.Remove(type);

                return true;
            }

            return false;
        }

        private void btnLoadKeytab_Click(object sender, EventArgs e)
        {
            using (var dialog = new OpenFileDialog())
            {
                var result = dialog.ShowDialog(this);

                if (result == DialogResult.OK)
                {
                    LoadKeytab(dialog.FileName);
                }
            }
        }

        private KeyTable table;

        private void LoadKeytab(string fileName)
        {
            try
            {
                var keytab = new KeyTable(File.ReadAllBytes(fileName));

                if (keytab.Entries.Any())
                {
                    table = keytab;

                    lblKeytab.Text = fileName;

                    if (string.IsNullOrWhiteSpace(txtTicket.Text))
                    {
                        var formatted = GenerateFormattedKeyTable(table);

                        var serialized = FormatSerialize(new { KeyTable = formatted });

                        DisplayDeconstructed(serialized, "KeyTable");
                    }
                }
            }
            catch (Exception ex)
            {
                lblKeytab.Text = "";
                this.ShowError(ex);
            }
        }

        private void btnClear_Click(object sender, EventArgs e)
        {
            txtTicket.Text = "";
            txtDump.Text = "";
            txtHost.Text = "";
            txtKey.Text = "";
            chkEncodedKey.Checked = false;

            treeView1.Nodes.Clear();
            table = null;
            lblKeytab.Text = "";
        }

        private void btnRequest_Click(object sender, EventArgs e)
        {
            try
            {
                RequestLocalTicket();
            }
            catch (Exception ex)
            {
                ShowError(ex);
            }
        }

        private void btnExport_Click(object sender, EventArgs e)
        {
            using (var dialog = new SaveFileDialog
            {
                Filter = "txt files (*.txt)|*.txt|All files (*.*)|*.*",
                FilterIndex = 2,
                RestoreDirectory = true
            })
            {
                if (dialog.ShowDialog() == DialogResult.OK)
                {
                    using (var stream = dialog.OpenFile())
                    {
                        ExportFile(stream);
                    }
                }
            }
        }

        private void ExportFile(Stream stream)
        {
            var header = new StringBuilder();

            header.AppendLine("GET http://fakeserver/fakenegotiate HTTP/1.1");
            header.AppendLine("User-Agent: kerberos/net");
            header.AppendLine("Pragma: no-cache");
            header.AppendLine("Host: fakeserver");
            header.AppendFormat("WWW-Authenticate: Negotiate {0}\r\n", txtTicket.Text);
            header.AppendLine("Accept-Language: en-US");
            header.AppendLine("Accept-Encoding: gzip, deflate");
            header.AppendLine("Connection: close");
            header.AppendLine();

            using (var writer = new StreamWriter(stream))
            {
                writer.Write(HexDump(Encoding.ASCII.GetBytes(header.ToString())));
                writer.Flush();
            }
        }

        public static string HexDump(byte[] bytes, int bytesPerLine = 16)
        {
            var sb = new StringBuilder();

            for (int line = 0; line < bytes.Length; line += bytesPerLine)
            {
                var lineBytes = bytes.Skip(line).Take(bytesPerLine).ToArray();

                sb.AppendFormat("{0:x8} ", line);

                sb.Append(string.Join(" ", lineBytes.Select(b => b.ToString("x2")).ToArray()).PadRight((bytesPerLine * 3)));

                sb.Append(" ");

                sb.Append(new string(lineBytes.Select(b => b < 32 ? '.' : (char)b).ToArray()));
                sb.AppendLine();
            }

            return sb.ToString();
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
            var winErrorCode = LsaNtStatusToWinError(
                LsaRetrievePrivateData(lsaPolicyHandle, ref secretName, out IntPtr privateData)
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
