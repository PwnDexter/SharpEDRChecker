using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpEDRChecker
{
    internal static class EDRMatcher
    {
        private static List<string> _decodedKeywords;
        private static readonly object _lock = new object();

        private static void EnsureKeywordsDecoded()
        {
            if (_decodedKeywords == null)
            {
                lock (_lock) // Ensure thread-safe initialization
                {
                    if (_decodedKeywords == null)
                    {
                        _decodedKeywords = EDRData.edrlist
                            .Select(encoded => Encoding.UTF8.GetString(System.Convert.FromBase64String(encoded)))
                            .ToList();
                    }
                }
            }
        }

        internal static List<string> GetMatches(string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return new List<string>();
            }

            EnsureKeywordsDecoded();
            return _decodedKeywords.Where(edr => input.ToLower().Contains(edr.ToLower())).ToList();
        }
    }
}
