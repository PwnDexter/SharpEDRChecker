# SharpEDRChecker
C# Implementation of Invoke-EDRChecker (https://github.com/PwnDexter/Invoke-EDRChecker). Checks running processes, process metadata, Dlls loaded into your current process and the each DLLs metadata, common install directories, installed services and each service binaries metadata, installed drivers and each drivers metadata, all for the presence of known defensive products such as AV's, EDR's and logging tools. Catches hidden EDRs as well via its metadata checks, more info in a blog post coming soon.

This binary can be loaded into your C2 server as well, load the module then run it. Note: this binary is now included in PoshC2 so no need to manually add it.

I will continue to add and improve the list when time permits. A full roadmap can be found below.

Find me on twitter @PwnDexter for any issues or questions!

## Install

```
git clone https://github.com/PwnDexter/SharpEDRChecker.git
```

## Compile

XXX

## Usage

Once the binary has been loaded onto your host or into your C2 of choice, you can use the following commands:

Run the binary against the local host and perform checks based on current user integrity:
```
.\SharpEDRChecker.exe
run-exe SharpEDRChecker.Program SharpEDRChecker
```

## Example Output

XXX

## Roadmap
- [ ] - Add more EDR Products - never ending
- [ ] - Test across more Windows and .NET versions
- [ ] - Add remote host query capability
- [ ] - Port to python for unix/macos support
