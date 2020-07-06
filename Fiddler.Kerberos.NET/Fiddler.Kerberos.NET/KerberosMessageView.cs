using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Security;
using System.Windows.Forms;
using Fiddler.Kerberos.NET.Json;
using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.SpNego;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;

namespace Fiddler.Kerberos.NET
{
    public partial class KerberosMessageView : UserControl
    {
        public KerberosMessageView()
        {
            InitializeComponent();

            this.Dock = DockStyle.Fill;
        }

        private string warning;

        public string Warning
        {
            get { return warning; }
            set
            {
                ResetLayout();

                warning = value;

                if (!string.IsNullOrWhiteSpace(warning))
                {
                    SetBaseNode(warning);
                }
            }
        }

        private void SetBaseNode(string text)
        {
            tvMessageStructure.Nodes.Add(text);
        }

        public void ResetLayout()
        {
            messageParsed = false;

            warning = null;
            tvMessageStructure.Nodes.Clear();
        }

        private bool messageParsed = false;

        internal void ProcessMessage(byte[] message, string source = null)
        {
            if (messageParsed)
            {
                return;
            }

            ResetLayout();

            object parsedMessage = null;

            try
            {
                parsedMessage = MessageParser.Parse(message);
            }
            catch { }

            if (parsedMessage == null)
            {
                try
                {
                    var nego = NegotiationToken.Decode(message);

                    if (nego.ResponseToken != null)
                    {
                        parsedMessage = MessageParser.Parse(nego.ResponseToken.ResponseToken.Value);
                    }
                }
                catch { }
            }

            if (parsedMessage is NtlmContextToken ntlm)
            {
                ProcessNtlm(ntlm, source);
            }
            else if (parsedMessage is NegotiateContextToken nego)
            {
                ProcessNegotiate(nego.Token, source);
            }
            else if (parsedMessage is KerberosContextToken kerb)
            {
                ProcessKerberos(kerb, source);
            }

            try
            {
                if (KdcProxyMessage.TryDecode(message, out KdcProxyMessage proxyMessage))
                {
                    ProcessKdcProxy(proxyMessage, source);
                }
            }
            catch { }
        }

        private void ProcessKdcProxy(KdcProxyMessage proxyMessage, string source)
        {
            var message = proxyMessage.UnwrapMessage();

            var kdcBody = new
            {
                AsReq = TryDecode(message, m => KrbAsReq.DecodeApplication(m)),
                AsRep = TryDecode(message, m => KrbAsRep.DecodeApplication(m)),
                TgsReq = TryDecode(message, m => KrbTgsReq.DecodeApplication(m)),
                TgsRep = TryDecode(message, m => KrbTgsRep.DecodeApplication(m)),
                KrbError = TryDecode(message, m => KrbError.DecodeApplication(m))
            };

            if (kdcBody.AsReq != null)
            {
                ExplodeObject(kdcBody.AsReq, $"AS-REQ ({source})");
            }
            else if (kdcBody.AsRep != null)
            {
                ExplodeObject(kdcBody.AsRep, $"AS-REP ({source})");
            }
            else if (kdcBody.TgsReq != null)
            {
                ExplodeObject(kdcBody.TgsReq, $"TGS-REQ ({source})");
            }
            else if (kdcBody.TgsRep != null)
            {
                ExplodeObject(kdcBody.TgsRep, $"TGS-REP ({source})");
            }
            else if (kdcBody.KrbError != null)
            {
                ExplodeObject(kdcBody.KrbError, $"Krb-Error ({source})");
            }
        }

        private static object TryDecode(ReadOnlyMemory<byte> kerbMessage, Func<ReadOnlyMemory<byte>, object> p)
        {
            try
            {
                return p(kerbMessage);
            }
            catch (Exception ex)
            {
                FiddlerApplication.Log.LogString($"[Kerberos debug]: failed to parse message {ex.Message}");

                return null;
            }
        }

        private void ProcessKerberos(KerberosContextToken kerb, string source)
        {
            if (kerb.KrbApReq != null)
            {
                ExplodeObject(kerb.KrbApReq, $"Kerberos AP-REQ ({source})");
            }
            else if (kerb.KrbApRep != null)
            {
                ExplodeObject(kerb.KrbApRep, $"Kerberos AP-REP ({source})");
            }
        }

        private void ProcessNegotiate(NegotiationToken token, string source)
        {
            var parsed = MessageParser.Parse(token.InitialToken.MechToken.Value);

            ExplodeObject(parsed, $"Kerberos Message ({source})");
        }

        private void ProcessNtlm(NtlmContextToken ntlm, string source)
        {
            ExplodeObject(ntlm.Token, $"NTLM Message ({source})");
        }

        private void ExplodeObject(object thing, string baseNodeText)
        {
            tvMessageStructure.ContextMenu = CreateContextMenu(tvMessageStructure);

            tvMessageStructure.BeginUpdate();

            TreeNode node = tvMessageStructure.SelectedNode;

            if (node == null || tvMessageStructure.Nodes.Count <= 0)
            {
                node = new TreeNode("Message");

                tvMessageStructure.Nodes.Add(node);
                tvMessageStructure.SelectedNode = node;
            }

            ExplodeObject(thing, baseNodeText, node);

            tvMessageStructure.EndUpdate();

            messageParsed = true;
        }

        private static void ExplodeObject(object thing, string baseNodeText, TreeNode tree)
        {
            var formattedJson = FormatSerialize(thing);

            CreateTreeView(formattedJson, baseNodeText, tree);
        }

        private static readonly JsonSerializerSettings JsonSettings = new JsonSerializerSettings
        {
            Formatting = Formatting.Indented,
            Converters = new JsonConverter[] { new StringEnumConverter(), new BinaryConverter(), new RpcConverter() },
            ContractResolver = new KerberosIgnoreResolver()
        };

        private static string FormatSerialize(object obj)
        {
            return JsonConvert.SerializeObject(obj, JsonSettings);
        }

        private static void OnClickCopy(object sender, EventArgs e)
        {
            if (sender is MenuItem item &&
                item.Parent is ContextMenu menu)
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

        private static void OnClickSendToTextWizard(object sender, EventArgs e)
        {
            if (sender is MenuItem item &&
               item.Parent is ContextMenu menu)
            {
                if (menu.Tag is TreeNode node)
                {
                    FiddlerApplication.UI.actShowTextWizard(node.Text);
                }
                else if (menu.Tag is TreeView tree)
                {
                    FiddlerApplication.UI.actShowTextWizard(tree.SelectedNode?.Text);
                }
            }
        }

        private static void OnClickDecodeAsAdWin2kPac(object sender, EventArgs e)
        {
            ParseNode(sender, out string text, out TreeNode parentNode);

            if (!string.IsNullOrWhiteSpace(text))
            {
                try
                {
                    DecodeAsAdWin2kPac(Convert.FromBase64String(text), parentNode);
                }
                catch (Exception ex)
                {
                    FiddlerApplication.Log.LogString($"DecodeAsAdWin2kPac exception: {ex}");
                }
            }
        }

        private static void OnClickDecodeAsAdIfRelevant(object sender, EventArgs e)
        {
            ParseNode(sender, out string text, out TreeNode parentNode);

            if (!string.IsNullOrWhiteSpace(text))
            {
                try
                {
                    DecodeAsAdIfRelevant(Convert.FromBase64String(text), parentNode);
                }
                catch (Exception ex)
                {
                    FiddlerApplication.Log.LogString($"DecodeAsAdIfRelevant exception: {ex}");
                }
            }
        }

        private static void DecodeAsAdWin2kPac(byte[] bytes, TreeNode parentNode)
        {
            var pac = new PrivilegedAttributeCertificate(new KrbAuthorizationData { Data = bytes, Type = AuthorizationDataType.AdWin2kPac });

            ExplodeObject(pac, "Privilege Attribute Certificate", parentNode);
        }

        private static void DecodeAsAdIfRelevant(byte[] bytes, TreeNode parentNode)
        {
            var seq = KrbAuthorizationDataSequence.Decode(bytes);

            foreach (var authz in seq.AuthorizationData)
            {
                ExplodeObject(authz, "AuthorizationData", parentNode);
            }
        }

        private static void OnClickDecodeAsApReq(object sender, EventArgs e)
        {
            ParseNode(sender, out string text, out TreeNode parentNode);

            if (!string.IsNullOrWhiteSpace(text))
            {
                try
                {
                    DecodeAsApReq(Convert.FromBase64String(text), parentNode);
                }
                catch (Exception ex)
                {
                    FiddlerApplication.Log.LogString($"DecodeAsApReq exception: {ex}");
                }
            }
        }

        private static void ParseNode(object sender, out string text, out TreeNode parentNode)
        {
            text = null;
            parentNode = null;

            if (sender is MenuItem item &&
                item.Parent is MenuItem parentItem &&
                parentItem.Parent is ContextMenu menu)
            {
                if (menu.Tag is TreeNode node)
                {
                    parentNode = node;
                    text = node.Text;
                }
                else if (menu.Tag is TreeView tree)
                {
                    text = tree.SelectedNode?.Text;
                    parentNode = tree.SelectedNode;
                }
            }
        }

        private static void DecodeAsApReq(byte[] bytes, TreeNode parentNode)
        {
            var apReq = KrbApReq.DecodeApplication(bytes);

            ExplodeObject(apReq, "AP-REQ", parentNode);
        }

        private static ContextMenu CreateContextMenu(object tag)
        {
            return new ContextMenu(new[]
            {
                new MenuItem("Copy", OnClickCopy, Shortcut.CtrlC),
                new MenuItem("Send to TextWizard", OnClickSendToTextWizard, Shortcut.CtrlE),
                new MenuItem("Decode As...", new []
                {
                    new MenuItem("AP-REQ", OnClickDecodeAsApReq, Shortcut.CtrlShiftA),
                    new MenuItem("Ad-If-Relevant", OnClickDecodeAsAdIfRelevant, Shortcut.CtrlShiftR),
                    new MenuItem("Ad-Win2k-Pac", OnClickDecodeAsAdWin2kPac, Shortcut.CtrlShiftP),
                })
            })
            {
                Tag = tag
            };
        }

        private static void CreateTreeView(string json, string label, TreeNode tree)
        {
            tree.Nodes.Clear();

            var root = new TreeNode(label);

            CreateNewRoot(json, root);

            tree.Nodes.Add(root);

            tree.ExpandAll();

            if (tree.Nodes.Count > 0)
            {
                tree.Nodes[0].EnsureVisible();
            }
        }

        private static void CreateNewRoot(string json, TreeNode root)
        {
            using (var reader = new StringReader(json))
            using (var jsonReader = new JsonTextReader(reader))
            {
                var obj = JToken.Load(jsonReader);

                AddNode(obj, root, scope: "");
            }
        }

        private static void AddNode(JToken token, TreeNode inTreeNode, string scope, bool decryptable = false)
        {
            if (token == null)
            {
                return;
            }

            if (token is JValue)
            {
                var node = new TreeNode(token.ToString());

                node.ContextMenu = CreateContextMenu(node);

                inTreeNode.Nodes.Add(node);
            }
            else if (token is JObject obj)
            {
                if (decryptable)
                {
                    ConfigureDecryption(inTreeNode, token, scope);
                }

                foreach (var property in obj.Properties())
                {
                    var localScope = scope;

                    ExtendScope(ref localScope, property.Name);

                    var childNode = new TreeNode(property.Name);

                    childNode.ContextMenu = CreateContextMenu(childNode);

                    decryptable = IsDecryptable(localScope);

                    AddNode(property.Value, childNode, localScope, decryptable);

                    inTreeNode.Nodes.Add(childNode);
                }
            }
            else if (token is JArray array)
            {
                for (int i = 0; i < array.Count; i++)
                {
                    var value = array[i];

                    var localScope = scope;

                    if (value.Type == JTokenType.String)
                    {
                        ExtendScope(ref localScope, $"[{i}]");

                        AddNode(value, inTreeNode, localScope);
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

                        var node = new TreeNode(typeName);
                        node.ContextMenu = CreateContextMenu(node);

                        var childNode = inTreeNode.Nodes[inTreeNode.Nodes.Add(node)];

                        ExtendScope(ref localScope, typeName);

                        AddNode(value, childNode, localScope);
                    }
                }
            }
        }

        private static void ExtendScope(ref string localScope, string name)
        {
            if (string.IsNullOrEmpty(localScope))
            {
                localScope = name;
            }
            else
            {
                localScope += $".{name}";
            }
        }

        private static void ConfigureDecryption(TreeNode inTreeNode, JToken token, string scope)
        {
            inTreeNode.ContextMenu = new ContextMenu(new[]
            {
                new MenuItem("Decrypt", DecryptMessage)
                {
                    Tag = token,
                    Name = scope
                }
            })
            {
                Tag = inTreeNode
            };
        }

        private static void DecryptMessage(object sender, EventArgs e)
        {
            if (sender is MenuItem item && item.Tag is JToken token)
            {
                try
                {
                    PopAndDecrypt(token, item);
                }
                catch (SecurityException ex)
                {
                    MessageBox.Show($"Decryption failed: {ex.Message}", "Couldn't decrypt the message", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Something else failed: {ex.Message}", "Couldn't decrypt the message", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private static void PopAndDecrypt(JToken token, MenuItem item)
        {
            var creds = CredUI.Prompt("Decryption Credentials", "Provide the credentials used to decrypt this message");

            if (string.IsNullOrWhiteSpace(creds?.Password))
            {
                return;
            }

            if (!EncryptedFields.TryGetValue(item.Name, out (KeyUsage usage, Func<ReadOnlyMemory<byte>, object> decoder) decoder))
            {
                return;
            }

            var serializer = new JsonSerializer();

            foreach (var converter in JsonSettings.Converters)
            {
                serializer.Converters.Add(converter);
            }

            var encryptedData = token.ToObject<KrbEncryptedData>(serializer);

            object decrypted = null;

            try
            {
                var key = ConvertKey(creds, tryAsKey: false);

                decrypted = encryptedData.Decrypt(key, decoder.usage, decoder.decoder);
            }
            catch (Exception ex)
            {
                FiddlerApplication.Log.LogString($"[Kerberos debug] Decrypt failed as password. Trying as key next. Exception: {ex}");
            }

            try
            {
                var key = ConvertKey(creds, tryAsKey: true);

                decrypted = encryptedData.Decrypt(key, decoder.usage, decoder.decoder);
            }
            catch (Exception ex)
            {
                FiddlerApplication.Log.LogString($"[Kerberos debug] Decrypt failed as key. Nothing else to try. Exception: {ex}");
            }

            if (decrypted == null)
            {
                throw new SecurityException($"The provided key couldn't decrypt the message as either a password or as the derived key");
            }

            var serialized = FormatSerialize(decrypted);

            var node = item.Parent.Tag as TreeNode;

            CreateNewRoot(serialized, node);

            node.ExpandAll();
        }

        private static KerberosKey ConvertKey(NetworkCredential creds, bool tryAsKey)
        {
            string domain = creds.Domain ?? "";

            var userSplit = creds.UserName.Split(new[] { '\\', '@' }, StringSplitOptions.RemoveEmptyEntries);

            string username = userSplit[0];

            if (userSplit.Length > 1)
            {
                domain = userSplit[1];
            }

            var name = KrbPrincipalName.FromString(username, realm: domain);

            if (tryAsKey)
            {
                return new KerberosKey(
                    key: Convert.FromBase64String(creds.Password),
                    principal: new PrincipalName(PrincipalNameType.NT_SRV_HST, domain, name.Name),
                    host: username
                );
            }
            else
            {
                return new KerberosKey(
                    creds.Password,
                    new PrincipalName(PrincipalNameType.NT_SRV_HST, domain, name.Name),
                    host: username
                );
            }
        }

        private static readonly Dictionary<string, (KeyUsage usage, Func<ReadOnlyMemory<byte>, object> decoder)> EncryptedFields
            = new Dictionary<string, (KeyUsage usage, Func<ReadOnlyMemory<byte>, object> decoder)>
            {
                { "KrbApReq.Ticket.EncryptedPart", (KeyUsage.Ticket, b => KrbEncTicketPart.DecodeApplication(b)) },
                { "KrbApReq.Authenticator", (KeyUsage.ApReqAuthenticator, b => KrbAuthenticator.DecodeApplication(b)) },
                { "Ticket.EncryptedPart", (KeyUsage.Ticket, b => KrbEncTicketPart.DecodeApplication(b)) },
            };

        private static bool IsDecryptable(string scope)
        {
            Debug.WriteLine(scope);
            return EncryptedFields.Keys.Any(s => string.Equals(s, scope, StringComparison.InvariantCultureIgnoreCase));
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
    }
}
