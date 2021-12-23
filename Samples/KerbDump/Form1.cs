using System;
using System.Buffers;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using KerbDump.Properties;
using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Pac;
using Kerberos.NET.Reflection;
using Kerberos.NET.Win32;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;

#pragma warning disable IDE1006 // Naming Styles

namespace KerbDump
{
    public partial class Form1 : Form
    {
        private const string RequestTemplateText = "Request for {0}";

        private readonly ContextMenuStrip exportMenu = new ContextMenuStrip();

        private readonly Font DefaultTreeFont;
        private readonly int splitter1Default;

        public Form1()
        {
            this.AutoScaleDimensions = new System.Drawing.SizeF(96F, 96F);
            this.AutoScaleMode = AutoScaleMode.Dpi;

            this.InitializeComponent();

            this.DefaultTreeFont = new Font(this.treeView1.Font.FontFamily, this.treeView1.Font.Size, FontStyle.Italic);

            this.exportMenu.Items.Add("Export to WireShark", null, this.ExportWireshark);
            this.exportMenu.Items.Add("Export to Keytab", null, this.ExportKeytab);

            this.ddlKeyType.SelectedIndex = 0;
            this.ddlKeyType.DropDownStyle = ComboBoxStyle.DropDownList;

            this.btnExport.Click += (s, e) =>
            {
                this.exportMenu.Show(this.btnExport, new Point());
            };

            this.splitter1Default = this.splitContainer1.SplitterDistance;

            this.splitContainer1.DoubleClick += (s, e) =>
            {
                if (this.splitContainer1.SplitterDistance >= this.splitter1Default)
                {
                    this.splitContainer1.SplitterDistance = 5;
                }
                else
                {
                    this.splitContainer1.SplitterDistance = this.splitter1Default;
                }
            };

            DecodeEvent += (s, e) =>
            {
                if (this.IsHandleCreated)
                {
                    this.Invoke((MethodInvoker)delegate ()
                    {
                        this.lblDecode.Text = $"Decoding 0x{e.Start:x4} - 0x{e.End:x4}";
                    });
                }
            };

            this.lblDecode.Text = "";
            this.lblKeytab.Text = "";

            CryptoService.RegisterCryptographicAlgorithm(EncryptionType.NULL, () => new NoopTransform());

            this.SetHost();

            this.txtHost.TextChanged += this.Host_Changed;

            this.txtHost.Text = this.hostName;
        }

        public string Ticket
        {
            get => this.txtTicket.Text;
            set => this.txtTicket.Text = value;
        }

        public bool Persistent { get; set; } = true;

        private readonly CancellationTokenSource cancellation = new CancellationTokenSource();

        private void Form1_Load(object sender, EventArgs e)
        {
            if (this.Persistent)
            {
                this.TryLoadPersistedSettings();
            }
            else if (!string.IsNullOrWhiteSpace(this.Ticket))
            {
                this.chkRemember.Checked = false;
                this.button1_Click(sender, e);
            }

            if (this.IsHandleCreated)
            {
                this.Invoke((MethodInvoker)delegate ()
                {
                    this.TopMost = true;
                    this.TopMost = false;
                });
            }
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            this.cancellation.Cancel();
        }

        private void CopyNodeValue(object sender, EventArgs e)
        {
            if (sender is ToolStripMenuItem item &&
                item.GetCurrentParent() is ToolStrip menu)
            {
                if (menu.Tag is TreeNode node)
                {
                    string text = StripEquals(node);

                    Clipboard.SetText(text);
                }
                else if (menu.Tag is TreeView tree)
                {
                    string text = StripEquals(tree.SelectedNode);

                    Clipboard.SetText(text);
                }
            }
        }

        private static string StripEquals(TreeNode node)
        {
            if (string.IsNullOrWhiteSpace(node?.Text))
            {
                return null;
            }

            var text = node.Text;

            var index = text.IndexOf('=');

            if (index > 0)
            {
                text = text.Substring(index + 1);
            }

            return text.Trim();
        }

        private void CopyNodeText(object sender, EventArgs e)
        {
            if (sender is ToolStripMenuItem item &&
                item.GetCurrentParent() is ToolStrip menu)
            {
                if (menu.Tag is TreeNode node)
                {
                    Clipboard.SetText(node.Text);
                }
                else if (menu.Tag is TreeView tree)
                {
                    Clipboard.SetText(tree.SelectedNode?.Text);
                }
            }
        }

        private void TryLoadPersistedSettings()
        {
            if (!Settings.Default.ShouldRemember)
            {
                this.chkRemember.Checked = false;

                return;
            }

            this.txtTicket.Text = Settings.Default.Ticket;
            this.txtKey.Text = this.Unprotect(Settings.Default.Secret);
            this.chkEncodedKey.Checked = Settings.Default.IsSecretEncoded;
            this.txtHost.Text = Settings.Default.Host;
            this.ddlKeyType.SelectedIndex = Settings.Default.SecretType;

            this.button1_Click(this, EventArgs.Empty);
        }

        private void SetHost()
        {
            this.hostName = Environment.MachineName.ToLowerInvariant();
        }

        string hostName = "";

        private void Host_Changed(object sender, EventArgs e)
        {
            this.hostName = this.txtHost.Text;

            if (!string.IsNullOrWhiteSpace(this.hostName))
            {
                var hostLabel = this.hostName.Split('.').First();

                if (hostLabel.Length > 15)
                {
                    hostLabel = hostLabel.Substring(0, 15) + "...";
                }

                this.btnRequest.Text = string.Format(RequestTemplateText, hostLabel);
            }
            else
            {
                this.btnRequest.Text = string.Format(RequestTemplateText, "<host>");
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            try
            {
                this.Decode();
            }
            catch (Exception ex)
            {
                this.ShowError(ex);
            }
        }

        private void Decode()
        {
            if (this.chkRemember.Checked)
            {
                this.TryPersistingValues();
            }
            else
            {
                this.ResetPersistedValues();
            }

            if (string.IsNullOrWhiteSpace(this.txtTicket.Text))
            {
                return;
            }

            if (!string.IsNullOrWhiteSpace(this.txtKey.Text) || this.table != null)
            {
                this.decryptDecoded = true;
                this.key = this.CreateKeytab();
            }

            this.Decode(this.txtTicket.Text);
        }

        private KeyTable CreateKeytab()
        {
            var key = this.table;

            var domain = Environment.GetEnvironmentVariable("USERDNSDOMAIN") ?? "";

            var host = this.txtHost.Text;

            var split = host.Split(new[] { '.' }, 2);

            if (split.Length == 2)
            {
                host = split[0];
                domain = split[1];
            }

            if (key == null)
            {
                if (string.Equals("Password", this.ddlKeyType.SelectedItem?.ToString(), StringComparison.OrdinalIgnoreCase))
                {
                    key = this.EncodePassword(domain, host);
                }
                else
                {
                    key = this.EncodeKerberosKey();
                }
            }

            return key;
        }

        private KeyTable EncodeKerberosKey()
        {
            var bytes = Convert.FromBase64String(this.txtKey.Text);

            var keys = new List<KerberosKey>();

            foreach (EncryptionType etype in Enum.GetValues(typeof(EncryptionType)))
            {
                if (CryptoService.SupportsEType(etype, allowWeakCrypto: true) && etype != EncryptionType.NULL)
                {
                    var transformer = CryptoService.CreateTransform(etype);

                    keys.Add(new KerberosKey(key: bytes.Take(transformer.KeySize).ToArray(), etype: etype));
                }
            }

            return new KeyTable(keys.ToArray());
        }

        private KeyTable EncodePassword(string domain, string host)
        {
            KeyTable key;

            if (this.chkEncodedKey.Checked)
            {
                var bytes = Convert.FromBase64String(this.txtKey.Text);

                key = new KeyTable(
                    new KerberosKey(
                        password: bytes,
                        principal: new PrincipalName(PrincipalNameType.NT_SRV_HST, domain, new[] { Environment.MachineName }),
                        host: host
                    )
                );
            }
            else
            {
                key = new KeyTable(
                    new KerberosKey(
                        this.txtKey.Text,
                        principalName: new PrincipalName(PrincipalNameType.NT_SRV_HST, domain, new[] { Environment.MachineName }),
                        host: string.IsNullOrWhiteSpace(host) ? null : host
                    )
                );
            }

            return key;
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

                Settings.Default.Ticket = this.txtTicket.Text;
                Settings.Default.Secret = this.Protect(this.txtKey.Text);
                Settings.Default.IsSecretEncoded = this.chkEncodedKey.Checked;
                Settings.Default.Host = this.txtHost.Text;
                Settings.Default.SecretType = this.ddlKeyType.SelectedIndex;

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
            this.CreateTreeView(ticket, label);
        }

        private bool decryptDecoded = false;
        private KeyTable key = null;
        private byte[] ticketBytes = null;

        private async Task<string> DecryptMessage(KeyTable key)
        {
            var validator = new KerberosValidator(key) { ValidateAfterDecrypt = ValidationActions.Pac };

            var decrypted = await validator.Validate(ticketBytes);

            var request = MessageParser.Parse(ticketBytes);

            var keytableFormat = this.GenerateFormattedKeyTable(key);

            var authenticated = await new KerberosAuthenticator(validator).Authenticate(ticketBytes) as KerberosIdentity;

            return this.FormatSerialize(new
            {
                Request = request,
                Decrypted = decrypted,
                Computed = new
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
                var keyBytes = k.Key.GetKey(
                    CryptoService.CreateTransform(EncryptionType.NULL)
                );

                var key = new KerberosKey(
                    Encoding.Unicode.GetString(keyBytes.ToArray()),
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
                Converters = new JsonConverter[] { new StringEnumArrayConverter(), new BinaryConverter(), new PacConverter() },
                ContractResolver = new KerberosIgnoreResolver()
            };

            return JsonConvert.SerializeObject(obj, settings);
        }

        private class PacConverter : JsonConverter
        {
            public override bool CanConvert(Type objectType)
            {
                return objectType == typeof(RpcFileTime) ||
                       objectType == typeof(RpcString) ||
                       objectType == typeof(RpcSid);
            }

            public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
            {
                throw new NotImplementedException();
            }

            public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
            {
                if (value.GetType() == typeof(RpcFileTime))
                {
                    var rpc = (RpcFileTime)value;
                    var dt = (DateTimeOffset)rpc;

                    var dtConverter = new IsoDateTimeConverter();

                    dtConverter.WriteJson(writer, dt, serializer);
                }
                else if (value.GetType() == typeof(RpcString))
                {
                    writer.WriteValue(value?.ToString());
                }
                else if (value.GetType() == typeof(RpcSid))
                {
                    var rpcSid = (RpcSid)value;

                    writer.WriteValue(rpcSid.ToSecurityIdentifier().Value);
                }
            }
        }

        private class BinaryConverter : JsonConverter
        {
            public override bool CanConvert(Type objectType)
            {
                Debug.WriteLine(objectType.Name);

                return objectType == typeof(ReadOnlyMemory<byte>) ||
                       objectType == typeof(ReadOnlyMemory<byte>?) ||
                       objectType == typeof(ReadOnlySequence<byte>) ||
                       objectType == typeof(ReadOnlyMemory<int>) ||
                       objectType == typeof(Memory<byte>);
            }

            public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
            {
                throw new NotImplementedException();
            }

            public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
            {
                Reflect.IsBytes(value, out ReadOnlyMemory<byte> mem);

                writer.WriteValue(Convert.ToBase64String(mem.ToArray()));
            }
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

                if (enumVal.Length == 0)
                {
                    writer.WriteNull();
                }
                else if (enumVal.Length == 1)
                {
                    writer.WriteValue(enumVal.First());
                }
                else
                {
                    writer.WriteStartArray();

                    foreach (var en in enumVal)
                    {
                        writer.WriteValue(en);
                    }

                    writer.WriteEndArray();
                }
            }
        }

        private void Decode(string ticket)
        {
            this.treeView1.Nodes.Clear();

            DecodeMessage(ticket).ContinueWith(async t =>
            {
                try
                {
                    string ticket;

                    if (decryptDecoded)
                    {
                        ticket = await DecryptMessage(key);
                    }
                    else
                    {
                        ticket = FormatTicket();
                    }

                    this.Invoke((MethodInvoker)delegate ()
                    {
                        this.DisplayDeconstructed(ticket, "Decoded Message");
                    });
                }
                catch (Exception ex)
                {
                    this.ShowError(ex);
                }
            });
        }

        private string FormatTicket()
        {
            if (this.ticketBytes == null)
            {
                return null;
            }

            var request = MessageParser.Parse(this.ticketBytes);

            var obj = new Dictionary<string, object>()
            {
                { "Request", request }
            };

            var nego = request as NegotiateContextToken;

            if (nego?.Token.InitialToken.MechToken != null)
            {
                obj["Negotiate"] = MessageParser.Parse(nego.Token.InitialToken.MechToken.Value);
            }

            obj["Keytab"] = this.GenerateFormattedKeyTable(this.table);

            return this.FormatSerialize(obj);
        }

        private class DecodeEventArgs : EventArgs
        {
            public int Start { get; set; }
            public int End { get; set; }
        }

        private delegate void DecodeStep(object sender, DecodeEventArgs e);
        private static event DecodeStep DecodeEvent;

        private Task DecodeMessage(string ticket)
        {
            return Task.Run(() => this.ticketBytes = DecodeInternal(ticket));
        }

        private byte[] DecodeInternal(string ticket)
        {
            if (!TryDecodeHex(ticket, out byte[] ticketBytes))
            {
                if (!TryDecodeBase64(ticket, out ticketBytes))
                {
                    throw new FormatException("Unknown Kerberos message format");
                }
            }

            for (var i = 0; i < ticketBytes.Length; i++)
            {
                if (this.cancellation.IsCancellationRequested)
                {
                    break;
                }

                var forwards = new ReadOnlyMemory<byte>(ticketBytes).Slice(i);

                for (var j = forwards.Length; j > 0; j--)
                {
                    if (this.cancellation.IsCancellationRequested)
                    {
                        break;
                    }

                    var backwards = forwards.Slice(0, j);

                    try
                    {
                        Debug.WriteLine($"Trying {i}-{j}");
                        DecodeEvent?.Invoke(null, new DecodeEventArgs { Start = i, End = j });
                        var decoded = MessageParser.Parse(backwards);
                        return backwards.ToArray();
                    }
                    catch (Exception e) when (e is not InvalidOperationException)
                    {
                        continue;
                    }
                }
            }

            return null;
        }

        private static bool TryDecodeHex(string ticket, out byte[] ticketBytes)
        {
            ticketBytes = null;

            try
            {
                ticket = StripWhitespace(ticket);
                ticketBytes = StringToByteArray(ticket);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        private static bool TryDecodeBase64(string ticket, out byte[] ticketBytes)
        {
            ticketBytes = null;

            try
            {
                ticket = StripWhitespace(ticket);

                ticketBytes = Convert.FromBase64String(ticket);

                return true;
            }
            catch
            {
                return false;
            }
        }

        private void btnDecodeLocal_Click(object sender, EventArgs e)
        {
            try
            {
                using (var secret = new LSASecret("$MACHINE.ACC"))
                {
                    secret.GetSecret(out byte[] bytes);

                    this.txtKey.Text = Convert.ToBase64String(bytes);
                }

                this.chkEncodedKey.Checked = true;

                this.button1_Click(sender, e);
            }
            catch (Exception ex)
            {
                this.ShowError(ex);
            }
        }

        private void ShowError(Exception ex)
        {
            this.treeView1.Nodes.Clear();

            var sb = new StringBuilder();

            sb.Append("Decoding Failed. \r\n\r\n");

            if (ex is AggregateException agg)
            {
                foreach (var aggEx in agg.InnerExceptions)
                {
                    sb.AppendFormat("{0}\r\n\r\n", aggEx.Message);
                }
            }
            else
            {
                sb.Append(ex.Message);
            }

            MessageBox.Show(this, sb.ToString(), ex.Message, MessageBoxButtons.OK, MessageBoxIcon.Error);

            //this.treeView1.Nodes.Add(sb.ToString());
        }

        private void RequestLocalTicket()
        {
            if (string.IsNullOrWhiteSpace(this.hostName))
            {
                this.SetHost();

                this.txtHost.Text = this.hostName;
            }

            SspiContext context = new SspiContext(spn: this.hostName);

            byte[] tokenBytes = context.RequestToken();

            this.txtTicket.Text = Convert.ToBase64String(tokenBytes);
        }

        private void CreateTreeView(string json, string label)
        {
            if (string.IsNullOrWhiteSpace(json))
            {
                return;
            }

            this.treeView1.BeginUpdate();

            this.treeView1.Nodes.Clear();

            using (var reader = new StringReader(json))
            using (var jsonReader = new JsonTextReader(reader))
            {
                var obj = JToken.Load(jsonReader);

                var root = new TreeNode(label);

                this.AddNode(obj, root);

                this.treeView1.Nodes.Add(root);

                this.treeView1.ExpandAll();
            }

            if (this.treeView1.Nodes.Count > 0)
            {
                this.treeView1.Nodes[0].EnsureVisible();
                this.treeView1.Nodes[0].NodeFont = new Font(this.treeView1.Font, FontStyle.Regular);
            }

            this.treeView1.EndUpdate();
        }

        private TreeNode MakeNode(string display)
        {
            var node = new TreeNode(display);

            node.ContextMenuStrip = new ContextMenuStrip { Tag = node };

            if (display.IndexOf(" = ") > 0)
            {
                node.ContextMenuStrip.Items.Add("Copy", null, this.CopyNodeText);
            }

            node.ContextMenuStrip.Items.Add("Copy Value", null, this.CopyNodeValue);

            return node;
        }

        private int AddNode(JToken token, TreeNode inTreeNode)
        {
            if (token == null)
            {
                return 0;
            }

            if (token.Path.Split('.').Length == 1)
            {
                inTreeNode.NodeFont = new Font(this.DefaultTreeFont, FontStyle.Bold);
            }

            if (token is JValue)
            {
                inTreeNode.Nodes.Add(this.MakeNode(token.ToString()));

                return 0;
            }
            else if (token is JObject obj)
            {
                int children = 0;

                foreach (var property in obj.Properties())
                {
                    children++;

                    if (property.Value is JValue)
                    {
                        var childNode = this.MakeNode($"{property.Name} = {property.Value}");

                        if (string.IsNullOrWhiteSpace(property.Value.ToString()))
                        {
                            childNode.NodeFont = this.DefaultTreeFont;
                        }

                        inTreeNode.Nodes.Add(childNode);
                    }
                    else
                    {
                        var childNode = this.MakeNode(property.Name);

                        var childrenAdded = this.AddNode(property.Value, childNode);

                        inTreeNode.Nodes.Add(childNode);

                        if (childrenAdded == 0)
                        {
                            childNode.NodeFont = this.DefaultTreeFont;
                        }
                    }
                }

                return children;
            }
            else if (token is JArray array)
            {
                for (int i = 0; i < array.Count; i++)
                {
                    var value = array[i];

                    if (value.Type == JTokenType.String)
                    {
                        if (array.Count == 1)
                        {
                            inTreeNode.Text += $" = {value}";
                        }
                        else
                        {
                            this.AddNode(value, inTreeNode);
                        }
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

                        var childNode = inTreeNode.Nodes[inTreeNode.Nodes.Add(this.MakeNode(typeName))];

                        this.AddNode(value, childNode);
                    }
                }

                return array.Count;
            }

            return 0;
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
                    this.LoadKeytab(dialog.FileName);
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
                    this.table = keytab;

                    this.lblKeytab.Text = fileName;

                    if (string.IsNullOrWhiteSpace(this.txtTicket.Text))
                    {
                        var formatted = this.GenerateFormattedKeyTable(this.table);

                        var serialized = this.FormatSerialize(new { KeyTable = formatted });

                        this.DisplayDeconstructed(serialized, "KeyTable");
                    }
                }
            }
            catch (Exception ex)
            {
                this.lblKeytab.Text = "";
                this.ShowError(ex);
            }
        }

        private void btnClear_Click(object sender, EventArgs e)
        {
            this.splitContainer1.SplitterDistance = this.splitter1Default;

            this.txtTicket.Text = "";
            this.txtHost.Text = "";
            this.txtKey.Text = "";
            this.chkEncodedKey.Checked = false;

            this.treeView1.Nodes.Clear();
            this.table = null;
            this.lblKeytab.Text = "";
        }

        private void btnRequest_Click(object sender, EventArgs e)
        {
            try
            {
                this.RequestLocalTicket();
            }
            catch (Exception ex)
            {
                this.ShowError(ex);
            }
        }

        private void ExportWireshark(object sender, EventArgs e)
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
                        this.ExportWireSharkFile(stream);
                    }
                }
            }
        }

        private void ExportKeytab(object sender, EventArgs e)
        {
            using (var dialog = new SaveFileDialog
            {
                Filter = "keytab files (*.ketab)|*.keytab|All files (*.*)|*.*",
                FilterIndex = 2,
                RestoreDirectory = true
            })
            {
                if (dialog.ShowDialog() == DialogResult.OK)
                {
                    using (var stream = dialog.OpenFile())
                    {
                        this.ExportKeytabFile(stream);
                    }
                }
            }
        }

        private void ExportKeytabFile(Stream stream)
        {
            var keytab = this.CreateKeytab();

            using (var writer = new BinaryWriter(stream))
            {
                keytab.Write(writer);

                writer.Flush();
            }
        }

        private void ExportWireSharkFile(Stream stream)
        {
            var header = new StringBuilder();

            header.AppendLine("GET http://fakeserver/fakenegotiate HTTP/1.1");
            header.AppendLine("User-Agent: kerberos/net");
            header.AppendLine("Pragma: no-cache");
            header.AppendLine("Host: fakeserver");
            header.AppendFormat("WWW-Authenticate: Negotiate {0}\r\n", this.txtTicket.Text);
            header.AppendLine("Accept-Language: en-US");
            header.AppendLine("Accept-Encoding: gzip, deflate");
            header.AppendLine("Connection: close");
            header.AppendLine();

            using (var writer = new StreamWriter(stream))
            {
                writer.Write(Hex.DumpHex(Encoding.ASCII.GetBytes(header.ToString())));
                writer.Flush();
            }
        }

        private void ddlKeyType_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (ddlKeyType.SelectedIndex == 0) // password
            {
                this.chkEncodedKey.Visible = true;
                this.txtHost.Visible = true;
                this.label4.Visible = true;
            }
            else
            {
                this.chkEncodedKey.Visible = false;
                this.txtHost.Visible = false;
                this.label4.Visible = false;
            }
        }

        private void splitContainer2_Panel2_Paint(object sender, PaintEventArgs e)
        {

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
            this.secretName = new LSA_UNICODE_STRING()
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
                    out this.lsaPolicyHandle
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
                LsaRetrievePrivateData(this.lsaPolicyHandle, ref this.secretName, out IntPtr privateData)
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
            var winErrorCode = LsaNtStatusToWinError(LsaClose(this.lsaPolicyHandle));

            if (winErrorCode != 0)
            {
                throw new Win32Exception(winErrorCode);
            }
        }
    }
}
