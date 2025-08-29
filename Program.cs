using System.DirectoryServices.Protocols;
using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using static System.Formats.Asn1.AsnWriter;

namespace LdapChangeNotifications
{
    public class ChangeNotifier : IDisposable
    {
        LdapConnection _connection;
        HashSet<IAsyncResult> _results = new HashSet<IAsyncResult>();
        public ChangeNotifier(LdapConnection connection)

        {
            _connection = connection;
            _connection.AutoBind = true;
        }

        public void Register(string dn, string[] attributes, SearchScope scope)

        {
            SearchRequest request = new SearchRequest(
                dn,
                "(objectClass=*)",
                scope,
                attributes
                );

            request.Controls.Add(new DirectoryNotificationControl());
            IAsyncResult result = _connection.BeginSendRequest(
                request,
                TimeSpan.FromDays(1),
                PartialResultProcessing.ReturnPartialResultsAndNotifyCallback,
                Notify,
                request
                );
            _results.Add(result);
        }

        private void Notify(IAsyncResult result)
        {
            PartialResultsCollection prc = _connection.GetPartialResults(result);
            foreach (SearchResultEntry entry in prc)
            {
                OnObjectChanged(new ObjectChangedEventArgs(entry));
            }
        }

        private void OnObjectChanged(ObjectChangedEventArgs args)
        {
            if (ObjectChanged != null)
            {
                ObjectChanged(this, args);
            }
        }

        public event EventHandler<ObjectChangedEventArgs> ObjectChanged;
        #region IDisposable Members
        public void Dispose()
        {
            foreach (var result in _results)
            {
                _connection.Abort(result);
            }
        }
        #endregion
    }

    public class ObjectChangedEventArgs : EventArgs
    {
        public ObjectChangedEventArgs(SearchResultEntry entry)

        {
            Result = entry;

        }
        public SearchResultEntry Result { get; set; }
    }

    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 4)
            {
                Console.WriteLine("[!] Usage: MonitorADIDNS.exe <username> <password> <dc> <dnsNodeDN>");
                Console.WriteLine("Example: MonitorADIDNS.exe amico AAAAaaaa!1 10.0.0.5 DC=srv5,DC=test.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=test,DC=local");
                return;
            }

            string username = args[0];
            string password = args[1];
            string dc = args[2];
            string dnsNodeDN = args[3];

            string[] attributes = { "dnsRecord" };
            LdapDirectoryIdentifier ldapUri = new LdapDirectoryIdentifier(dc);
            using (LdapConnection connect = new LdapConnection(ldapUri, new System.Net.NetworkCredential(username, password)))
            {
                Console.WriteLine("[*] Successful bind");

                // make an initial check to see if an A record already exists
                SearchRequest initialRequest = new SearchRequest(dnsNodeDN,
                    "(objectClass=*)",
                    SearchScope.Base,
                    attributes
                    );
                SearchResponse initialResponse = null;

                try
                {
                    initialResponse = (SearchResponse)connect.SendRequest(initialRequest);
                }
                catch (DirectoryOperationException ex)
                {
                    if (ex.Message.Contains("NO_OBJECT"))
                    {
                        Console.WriteLine("[!] The provided dnsNode does not exist");
                        return;
                    }
                }

                try
                {
                    foreach (SearchResultEntry entry in initialResponse.Entries)
                    {
                        foreach (byte[] rawInitial in entry.Attributes["dnsRecord"].GetValues(typeof(byte[])))
                        {
                            string ip = RecordToIPAddress(rawInitial);
                            if (ip == "")
                                continue;

                            Console.WriteLine("[*] The dnsNode already has an A record: " + ip);
                        }
                    }
                }
                catch (NullReferenceException ex)
                {
                    Console.WriteLine("[!] Could not perform initial search, read ACE could be missing. Will monitor for changes anyway, but we can't find the IP with LDAP");
                }

                using (ChangeNotifier notifier = new ChangeNotifier(connect))
                {
                    notifier.Register(dnsNodeDN, attributes, SearchScope.Base);
                    Console.WriteLine("[*] Registered a notification request");
                    notifier.ObjectChanged += new EventHandler<ObjectChangedEventArgs>(notifier_ObjectChanged);
                    Console.WriteLine("[*] Waiting for changes...");
                    Console.ReadLine();
                }
            }
        }

        static void notifier_ObjectChanged(object sender, ObjectChangedEventArgs e)
        {
            bool foundA = false;
            Console.WriteLine("[*] The dnsNode was modified!");
            if (e.Result.Attributes.Count > 0)
            {
                foreach (string attrib in e.Result.Attributes.AttributeNames)
                {
                    foreach (byte[] item in e.Result.Attributes[attrib].GetValues(typeof(byte[])))
                    {
                        string ip = RecordToIPAddress(item);
                        if (ip == "")
                            continue;

                        Console.WriteLine("[*] IP Address: " + ip);
                        foundA = true;
                    }
                }

                if (!foundA)
                    Console.WriteLine("[*] No A entry in dnsRecord yet");
            }

            else
            {
                Console.WriteLine("[!] Can't query dnsNode, read ACE may be missing");
            }
        }

        static string RecordToIPAddress(byte[] rawAttr)
        {
            // ignore records other than A (ID = 0x0001)
            if (!(rawAttr[2] == 0x01 && rawAttr[3] == 0x00))
                return "";

            // data of A records is the last 4 bytes
            byte[] rawAData = new byte[4];
            Array.Copy(rawAttr, rawAttr.Length - 4, rawAData, 0, 4);
            IPAddress addr = new IPAddress(rawAData);

            return addr.ToString();
        }
    }
}
