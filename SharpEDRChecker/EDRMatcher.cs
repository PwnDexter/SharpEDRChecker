using System.Collections.Generic;
using System.Linq;

namespace SharpEDRChecker
{
    internal static class EDRMatcher
    {
        internal static List<string> GetMatches(string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return new List<string>();
            }

            return EDRData.edrlist.Where(edr => input.ToLower().Contains(edr.ToLower())).ToList();
        }
    }
}
