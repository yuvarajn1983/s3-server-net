using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace Api.Security
{
    public class S3AuthorizationHeader
    {
        public string HashAlgorithm { get; private set; }
        public Credential Credentials { get; private set; }
        public IList<string> SignedHeaders { get; private set; }
        public string Signature { get; private set; }

        private S3AuthorizationHeader(string headerContents)
        {
            var authStringComponents = headerContents.Split(new char[] { ',', ' ' });
            HashAlgorithm = authStringComponents[0].Trim();
            for(int i = 1; i < authStringComponents.Length; i++)
            {
                string authComponent = authStringComponents[i].Trim();
                if (authComponent.StartsWith("Credential=", StringComparison.OrdinalIgnoreCase))
                {
                    var creds = authComponent.Replace("Credential=", "").Split(',');
                    if (creds.Length > 0)
                    {
                        Credentials = new Credential(creds[0]);
                    }
                }
                else if (authComponent.StartsWith("SignedHeaders=", StringComparison.OrdinalIgnoreCase))
                {
                    var sh = authComponent.Replace("SignedHeaders=", "").Split(';').ToList();
                    sh.Sort();
                    SignedHeaders = sh;
                }
                else if(authComponent.StartsWith("Signature=", StringComparison.OrdinalIgnoreCase))
                {
                    Signature = authComponent.Replace("Signature=", "");
                }
            }
        }

        public static S3AuthorizationHeader ParseHeader(string headerContents)
        {
            return new S3AuthorizationHeader(headerContents);
        }

        public struct Credential
        {
            public string AccessKeyId { get; private set; }
            public DateTime Date { get; private set; }
            public string Region { get; private set; }
            public string Service { get; private set; }

            public Credential(string credentialString) : this()
            {
                var components = credentialString.Split('/');
                if (components.Length == 5)
                {
                    AccessKeyId = components[0];
                    Date = DateTime.ParseExact(components[1], "yyyyMMdd", CultureInfo.InvariantCulture);
                    Region = components[2];
                    Service = components[3];
                }
            }
        }
    }
}
