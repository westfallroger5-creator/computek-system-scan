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
        private const int MaxCatalogBytes = 10 * 1024 * 1024;

        public static CatalogInfo Validate(byte[] content, string sourceDescription)
        {
            Dictionary<string, object> root = ParseCatalog(content);
            object[] products = ValidateRoot(root);
            return new CatalogInfo
            {
                Version = Convert.ToString(root["catalogVersion"]),
                ProductCount = products.Length,
                SourceDescription = sourceDescription,
                Content = content
            };
        }

        public static CatalogInfo Merge(CatalogInfo baseCatalog, byte[] supplementContent, string supplementDescription)
        {
            if (baseCatalog == null) throw new ArgumentNullException("baseCatalog");

            Dictionary<string, object> root = ParseCatalog(baseCatalog.Content);
            object[] baseProducts = ValidateRoot(root);
            Dictionary<string, object> supplement = ParseCatalog(supplementContent);
            object[] supplementalProducts = ValidateRoot(supplement);

            List<object> mergedProducts = new List<object>(baseProducts);
            HashSet<string> identifiers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (object item in baseProducts)
            {
                Dictionary<string, object> product = item as Dictionary<string, object>;
                identifiers.Add(Convert.ToString(product["id"]));
            }

            int added = 0;
            foreach (object item in supplementalProducts)
            {
                Dictionary<string, object> product = item as Dictionary<string, object>;
                string id = Convert.ToString(product["id"]);
                if (identifiers.Add(id))
                {
                    mergedProducts.Add(product);
                    added++;
                }
            }

            root["products"] = mergedProducts.ToArray();
            string supplementVersion = Convert.ToString(supplement["catalogVersion"]);
            root["catalogVersion"] = baseCatalog.Version + "+" + supplementVersion;

            JavaScriptSerializer serializer = NewSerializer();
            byte[] mergedContent = new UTF8Encoding(false).GetBytes(serializer.Serialize(root));
            CatalogInfo merged = Validate(mergedContent, baseCatalog.SourceDescription + " + " + supplementDescription);
            if (added == 0)
                merged.SourceDescription += " (no new product IDs)";
            return merged;
        }

        private static Dictionary<string, object> ParseCatalog(byte[] content)
        {
            if (content == null || content.Length == 0)
                throw new InvalidDataException("The remote-software signature catalog is empty.");
            if (content.Length > MaxCatalogBytes)
                throw new InvalidDataException("The remote-software signature catalog is larger than 10 MB.");

            string json = new UTF8Encoding(false, true).GetString(content);
            try
            {
                return NewSerializer().DeserializeObject(json) as Dictionary<string, object>;
            }
            catch (Exception exception)
            {
                throw new InvalidDataException("The remote-software signature catalog is not valid JSON.", exception);
            }
        }

        private static object[] ValidateRoot(Dictionary<string, object> root)
        {
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
            return products;
        }

        private static JavaScriptSerializer NewSerializer()
        {
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            serializer.MaxJsonLength = MaxCatalogBytes;
            return serializer;
        }
    }
}
