using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpEDRChecker
{
    internal class DriverChecker
    {
        [DllImport("psapi")]
        private static extern bool EnumDeviceDrivers(
            [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)][In][Out] UIntPtr[] ddAddresses,
            uint arraySizeBytes,
            [MarshalAs(UnmanagedType.U4)] out uint bytesNeeded);

        [DllImport("psapi")]
        private static extern int GetDeviceDriverBaseName(
            UIntPtr ddAddress,
            StringBuilder ddBaseName,
            int baseNameStringSizeChars);

        [DllImport("psapi")]
        private static extern int GetDeviceDriverFileName(
            UIntPtr ddAddress,
            StringBuilder ddBaseName,
            int baseNameStringSizeChars);

        internal static void CheckDrivers()
        {
            uint arraySize;
            uint arraySizeBytes;
            UIntPtr[] ddAddresses;
            uint bytesNeeded;
            bool success;

            // Figure out how large an array we need to hold the device driver 'load addresses'
            success = EnumDeviceDrivers(null, 0, out bytesNeeded);

            Console.WriteLine("Success? " + success);
            Console.WriteLine("Array bytes needed? " + bytesNeeded);

            if (!success)
            {
                Console.WriteLine("Call to EnumDeviceDrivers failed!");
                int error = Marshal.GetLastWin32Error();
                Console.WriteLine("The last Win32 Error was: " + error);
                return;
            }
            if (bytesNeeded == 0)
            {
                Console.WriteLine("Apparently, there were NO device drivers to enumerate.  Strange.");
                return;
            }
            // Allocate the array; as each ID is a 4-byte int, it should be 1/4th the size of bytesNeeded
            arraySize = bytesNeeded / (uint)UIntPtr.Size;
            arraySizeBytes = bytesNeeded;
            ddAddresses = new UIntPtr[arraySize];

            // Now fill it
            success = EnumDeviceDrivers(ddAddresses, arraySizeBytes, out bytesNeeded);

            if (!success)
            {
                Console.WriteLine("Call to EnumDeviceDrivers failed!");
                int error = Marshal.GetLastWin32Error();
                Console.WriteLine("The last Win32 Error was: " + error);
                return;
            }
            Console.WriteLine($"Number of drivers: {arraySize}");

            for (int i = 0; i < arraySize; i++)
            {
                // If the length of the device driver base name is over 1000 characters, good luck to it.  :-)
                StringBuilder driverFilePathsb = new StringBuilder(1000);
                StringBuilder driverBaseNamesb = new StringBuilder(1000);

                int result = GetDeviceDriverFileName(ddAddresses[i], driverFilePathsb, driverFilePathsb.Capacity);

                if(result == 0)
                {
                    int error = Marshal.GetLastWin32Error();
                    Console.WriteLine("The last Win32 Error was: " + error);
                    continue;
                }

                result = GetDeviceDriverBaseName(ddAddresses[i], driverBaseNamesb, driverBaseNamesb.Capacity);

                if (result == 0)
                {
                    int error = Marshal.GetLastWin32Error();
                    Console.WriteLine("The last Win32 Error was: " + error);
                    continue;
                }
                var driverFileName = driverFilePathsb.ToString();
                var driverBaseName = driverBaseNamesb.ToString();

                //FROM HERE

            }
        }
    }
}