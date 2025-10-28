using System;
using System.Collections.Generic;
using System.Linq;

namespace SharpEDRChecker
{
    internal static class EDRMatcher
    {
        // Use Lazy<T> for thread-safe, lazy initialization of the keyword list.
        // The keywords are pre-processed (converted to lowercase) for performance.
        private static readonly Lazy<List<string>> _keywords = new Lazy<List<string>>(() =>
            EDRData.edrlist
                .Select(keyword => keyword.ToLower())
                .Distinct() // Remove any duplicates
                .ToList()
        );

        internal static List<string> GetMatches(string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return new List<string>(); // Return empty list for empty input
            }

            var lowerInput = input.ToLower();
            return _keywords.Value.Where(edr => lowerInput.Contains(edr)).ToList();
        }
    }
}
