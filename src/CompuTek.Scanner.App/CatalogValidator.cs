using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Web.Script.Serialization;

namespace CompuTek.Scanner.App
{
    internal sealed class CatalogInfo
    {
        public string Version { get; set; }
        public int ProductCount { get; set; }
        public string SourceDescription { get; set; }
        public byte[] Content { get; set; }
    }

    internal static class CatalogValidator
    {
        public static CatalogInfo Validate(byte[] content, string sourceDescription)
        {
            if (content == null || content.Length == 0)
                throw new InvalidDataException("The remote-software signature catalog is empty.");
            if (content.Length > 10 * 1024 * 1024)
                throw new InvalidDataException("The remote-software signature catalog is larger than 10 MB.");

            string json = new UTF8Encoding(false, true).GetString(content);
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            serializer.MaxJsonLength = 10 * 1024 * 1024;
            Dictionary<string, object> root;
            try
            {
                root = serializer.DeserializeObject(json) as Dictionary<string, object>;
            }
            catch (Exception exception)
            {
                throw new InvalidDataException("The remote-software signature catalog is not valid JSON.", exception);
            }

            if (root == null || !root.ContainsKey("schemaVersion") || Convert.ToInt32(root["schemaVersion"]) != 1)
                throw new InvalidDataException("The signature catalog uses an unsupported schema version.");
            if (!root.ContainsKey("catalogVersion") || String.IsNullOrWhiteSpace(Convert.ToString(root["catalogVersion"])))
                throw new InvalidDataException("The signature catalog has no catalogVersion.");

            object[] products = root.ContainsKey("products") ? root["products"] as object[] : null;
            if (products == null || products.Length == 0)
                throw new InvalidDataException("The signature catalog contains no remote-software products.");

            HashSet<string> identifiers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (object item in products)
            {
                Dictionary<string, object> product = item as Dictionary<string, object>;
                if (product == null || !product.ContainsKey("id") || !product.ContainsKey("name"))
                    throw new InvalidDataException("Every signature entry must have an id and name.");
                string id = Convert.ToString(product["id"]);
                string name = Convert.ToString(product["name"]);
                if (String.IsNullOrWhiteSpace(id) || String.IsNullOrWhiteSpace(name))
                    throw new InvalidDataException("Every signature entry must have a non-empty id and name.");
                if (!identifiers.Add(id))
                    throw new InvalidDataException("The signature catalog contains a duplicate id: " + id);
            }

            if (root.ContainsKey("managedIdentities"))
            {
                Dictionary<string, object> managedIdentities = root["managedIdentities"] as Dictionary<string, object>;
                if (managedIdentities == null)
                    throw new InvalidDataException("Managed identities must be a JSON object.");
                Dictionary<string, object> syncro = managedIdentities != null && managedIdentities.ContainsKey("syncro")
                    ? managedIdentities["syncro"] as Dictionary<string, object>
                    : null;
                object[] hashes = syncro != null && syncro.ContainsKey("shopSubdomainSha256")
                    ? syncro["shopSubdomainSha256"] as object[]
                    : null;
                if (syncro != null && hashes == null)
                    throw new InvalidDataException("The approved Syncro identity list must be an array.");
                if (hashes != null)
                {
                    foreach (object hashValue in hashes)
                    {
                        string hash = Convert.ToString(hashValue);
                        if (hash.Length != 64 || !System.Text.RegularExpressions.Regex.IsMatch(hash, "^[A-Fa-f0-9]{64}$"))
                            throw new InvalidDataException("Every approved Syncro identity must be a 64-character SHA-256 value.");
                    }
                }
            }

            return new CatalogInfo
            {
                Version = Convert.ToString(root["catalogVersion"]),
                ProductCount = products.Length,
                SourceDescription = sourceDescription,
                Content = content
            };
        }
    }
}
