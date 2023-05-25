/****************************************************************************
 *   Modern .NET Control Console API wrapper                                *
 *   Copyright (C) 2023 PHTNC<>                                             *
 *                                                                          *
 *   This program is free software: you can redistribute it and/or modify   *
 *   it under the terms of the GNU General Public License as published by   *
 *   the Free Software Foundation, either version 3 of the License, or      *
 *   (at your option) any later version.                                    *
 *                                                                          *
 *   This program is distributed in the hope that it will be useful,        *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of         *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          *
 *   GNU General Public License for more details.                           *
 *                                                                          *
 *   You should have received a copy of the GNU General Public License      *
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>. *
 ****************************************************************************/

using System;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32;

public unsafe class CCAPI
{
    private readonly IntPtr CCAPIHandle;
    private readonly delegate* unmanaged[Cdecl]<byte*, int> CCAPIConnectPtr;
    private readonly delegate* unmanaged[Cdecl]<int> CCAPIDisconnectPtr;
    private readonly delegate* unmanaged[Cdecl]<int*, int> CCAPIGetConnectionStatusPtr;
    private readonly delegate* unmanaged[Cdecl]<int, byte*, int> CCAPISetConsoleIdsPtr;
    private readonly delegate* unmanaged[Cdecl]<int, int, byte*, int> CCAPISetBootConsoleIdsPtr;
    private readonly delegate* unmanaged[Cdecl]<uint, ulong, uint, byte*, int> CCAPIGetMemoryPtr;
    private readonly delegate* unmanaged[Cdecl]<uint, ulong, uint, byte*, int> CCAPISetMemoryPtr;
    private readonly delegate* unmanaged[Cdecl]<uint*, uint*, int> CCAPIGetProcessListPtr;
    private readonly delegate* unmanaged[Cdecl]<uint, byte*, int> CCAPIGetProcessNamePtr;
    private readonly delegate* unmanaged[Cdecl]<int*, int*, int> CCAPIGetTemperaturePtr;
    private readonly delegate* unmanaged[Cdecl]<int, int> CCAPIShutdownPtr;
    private readonly delegate* unmanaged[Cdecl]<int, int> CCAPIRingBuzzerPtr;
    private readonly delegate* unmanaged[Cdecl]<int, int, int> CCAPISetConsoleLedPtr;
    private readonly delegate* unmanaged[Cdecl]<uint*, uint*, uint*, int> CCAPIGetFirmwareInfoPtr;
    private readonly delegate* unmanaged[Cdecl]<int, byte*, int> CCAPIVshNotifyPtr;
    private readonly delegate* unmanaged[Cdecl]<int> CCAPIGetNumberOfConsolesPtr;
    private readonly delegate* unmanaged[Cdecl]<int, byte*, byte*, void> CCAPIGetConsoleInfoPtr;
    private readonly delegate* unmanaged[Cdecl]<int> CCAPIGetDllVersionPtr;

    public CCAPI(string? libraryPath)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new NotImplementedException("Control Console API is not officially implemented for your operating system!");
        }
        if (Environment.Is64BitProcess)
        {
            throw new NotImplementedException("Control Console API cannot run on 64 bit applications!");
        }

        if (string.IsNullOrEmpty(libraryPath))
        {
            // Credits: IMCSx https://github.com/iMCSx/PS3Lib/blob/master/src/api/CCAPI.cs#L126
            RegistryKey? Key = Registry.CurrentUser.OpenSubKey(@"Software\FrenchModdingTeam\CCAPI\InstallFolder");
            if (Key != null)
            {
                string? Path = Key.GetValue("path") as String;
                if (!string.IsNullOrEmpty(Path))
                {
                    libraryPath = Path + @"\CCAPI.dll";
                }
                else throw new IOException("[ERROR] CCAPI does not seem to be installed on your system. Make sure you installed it correctly!");
            }
        }

        if (File.Exists(libraryPath))
        {
            if (NativeLibrary.TryLoad(libraryPath, out CCAPIHandle))
            {
                CCAPIConnectPtr = (delegate* unmanaged[Cdecl]<byte*, int>)NativeLibrary.GetExport(CCAPIHandle, "CCAPIConnectConsole");
                CCAPIDisconnectPtr = (delegate* unmanaged[Cdecl]<int>)NativeLibrary.GetExport(CCAPIHandle, "CCAPIDisconnectConsole");
                CCAPIGetConnectionStatusPtr = (delegate* unmanaged[Cdecl]<int*, int>)NativeLibrary.GetExport(CCAPIHandle, "CCAPIGetConnectionStatus");
                CCAPISetConsoleIdsPtr = (delegate* unmanaged[Cdecl]<int, byte*, int>)NativeLibrary.GetExport(CCAPIHandle, "CCAPISetConsoleIds");
                CCAPISetBootConsoleIdsPtr = (delegate* unmanaged[Cdecl]<int, int, byte*, int>)NativeLibrary.GetExport(CCAPIHandle, "CCAPISetBootConsoleIds");
                CCAPIGetMemoryPtr = (delegate* unmanaged[Cdecl]<uint, ulong, uint, byte*, int>)NativeLibrary.GetExport(CCAPIHandle, "CCAPIGetMemory");
                CCAPISetMemoryPtr = (delegate* unmanaged[Cdecl]<uint, ulong, uint, byte*, int>)NativeLibrary.GetExport(CCAPIHandle, "CCAPISetMemory");
                CCAPIGetProcessListPtr = (delegate* unmanaged[Cdecl]<uint*, uint*, int>)NativeLibrary.GetExport(CCAPIHandle, "CCAPIGetProcessList");
                CCAPIGetProcessNamePtr = (delegate* unmanaged[Cdecl]<uint, byte*, int>)NativeLibrary.GetExport(CCAPIHandle, "CCAPIGetProcessName");
                CCAPIGetTemperaturePtr = (delegate* unmanaged[Cdecl]<int*, int*, int>)NativeLibrary.GetExport(CCAPIHandle, "CCAPIGetTemperature");
                CCAPIShutdownPtr = (delegate* unmanaged[Cdecl]<int, int>)NativeLibrary.GetExport(CCAPIHandle, "CCAPIShutdown");
                CCAPIRingBuzzerPtr = (delegate* unmanaged[Cdecl]<int, int>)NativeLibrary.GetExport(CCAPIHandle, "CCAPIRingBuzzer");
                CCAPISetConsoleLedPtr = (delegate* unmanaged[Cdecl]<int, int, int>)NativeLibrary.GetExport(CCAPIHandle, "CCAPISetConsoleLed");
                CCAPIGetFirmwareInfoPtr = (delegate* unmanaged[Cdecl]<uint*, uint*, uint*, int>)NativeLibrary.GetExport(CCAPIHandle, "CCAPIGetFirmwareInfo");
                CCAPIVshNotifyPtr = (delegate* unmanaged[Cdecl]<int, byte*, int>)NativeLibrary.GetExport(CCAPIHandle, "CCAPIVshNotify");
                CCAPIGetNumberOfConsolesPtr = (delegate* unmanaged[Cdecl]<int>)NativeLibrary.GetExport(CCAPIHandle, "CCAPIGetNumberOfConsoles");
                CCAPIGetConsoleInfoPtr = (delegate* unmanaged[Cdecl]<int, byte*, byte*, void>)NativeLibrary.GetExport(CCAPIHandle, "CCAPIGetConsoleInfo");
                CCAPIGetDllVersionPtr = (delegate* unmanaged[Cdecl]<int>)NativeLibrary.GetExport(CCAPIHandle, "CCAPIGetDllVersion");
            }
            else throw new IOException("[ERROR] Failed to load CCAPI!");
        }
        else throw new IOException(string.Format("[ERROR] Failed to find CCAPI in the {0} folder!", libraryPath));
    }

    public enum ConsoleIdType
    {
        Idps = 0,
        Psid = 1
    }

    public enum ShutdownMode
    {
        ActionShutdown = 1,
        ActionSoftReboot = 2,
        ActionHardReboot = 3
    }

    public enum ConsoleType
    {
        UNK = 0,
        CEX = 1,
        DEX = 2,
        TOOL = 3
    }

    public enum ColorLed
    {
        LedRed = 0,
        LedGreen = 1
    }

    public enum StatusLed
    {
        LedOff = 0,
        LedOn = 1,
        LedBlink = 2
    }

    public enum BuzzerType
    {
        BuzzerContinuous = 0,
        BuzzerSingle = 1,
        BuzzerDouble = 2,
        BuzzerTriple = 3
    }

    public enum NotifyIcon
    {
        NotifyInfo = 0,
        NotifyCaution = 1,
        NotifyFriend = 2,
        NotifySlider = 3,
        NotifyWrongWay = 4,
        NotifyDialog = 5,
        NotifyDalogShadow = 6,
        NotifyText = 7,
        NotifyPointer = 8,
        NotifyGrab = 9,
        NotifyHand = 10,
        NotifyPen = 11,
        NotifyFinger = 12,
        NotifyArrow = 13,
        NotifyArrowRight = 14,
        NotifyProgress = 15,
        NotifyTrophy1 = 16,
        NotifyTrophy2 = 17,
        NotifyTrophy3 = 18,
        NotifyTrophy4 = 19
    }

    public int CCAPIConnect(string IPAddress)
    {
        int len = IPAddress.Length;
        fixed (char* ptrIp = IPAddress)
        {
            byte* ptrIpAscii = stackalloc byte[len];
            Encoding.ASCII.GetBytes(ptrIp, len, ptrIpAscii, len);
            return CCAPIConnectPtr(ptrIpAscii);
        }
    }

    public int CCAPIDisconnect()
    {
        return CCAPIDisconnectPtr();
    }

    public bool CCAPIGetConnectionStatus()
    {
        int status;
        CCAPIGetConnectionStatusPtr(&status);
        return status != 0;
    }

    public int CCAPISetConsoleIds(ConsoleIdType idType, ReadOnlySpan<byte> Id)
    {
        if (Id.Length != 16)
        {
            return -1;
        }

        fixed (byte* ptrId = Id)
        {
            return CCAPISetConsoleIdsPtr((int)idType, ptrId);
        }
    }

    public int CCAPISetConsoleIds(ConsoleIdType idType, byte[] Id)
    {
        if (Id.Length != 16)
        {
            return -1;
        }

        fixed (byte* ptrId = Id)
        {
            return CCAPISetConsoleIdsPtr((int)idType, ptrId);
        }
    }

    public int CCAPISetConsoleIds(ConsoleIdType idType, string Id)
    {
        if (Id.Length != 32)
        {
            return -1;
        }

        byte* ptrId = stackalloc byte[32];
        HexStringToByteArray(Id, ptrId);
        return CCAPISetConsoleIdsPtr((int)idType, ptrId);
    }

    public int CCAPISetBootConsoleIds(ConsoleIdType type, bool disableBootId, ReadOnlySpan<byte> Id)
    {
        if (Id.Length != 32)
        {
            return -1;
        }

        fixed (byte* ptrId = Id)
        {
            return CCAPISetBootConsoleIdsPtr((int)type, disableBootId ? 1 : 0, ptrId);
        }
    }

    public int CCAPISetBootConsoleIds(ConsoleIdType type, bool disableBootId, byte[] Id)
    {
        if (Id.Length != 32)
        {
            return -1;
        }

        fixed (byte* ptrId = Id)
        {
            return CCAPISetBootConsoleIdsPtr((int)type, disableBootId ? 1 : 0, ptrId);
        }
    }

    public int CCAPISetBootConsoleIds(ConsoleIdType type, bool disableBootId, string Id)
    {
        if (Id.Length != 32)
        {
            return -1;
        }

        byte* ptrId = stackalloc byte[32];
        HexStringToByteArray(Id, ptrId);
        return CCAPISetBootConsoleIdsPtr((int)type, disableBootId ? 1 : 0, ptrId);
    }

    public int CCAPIGetMemory(uint pid, ulong address, uint size, byte[] data)
    {
        fixed (byte* ptrData = data)
        {
            return CCAPIGetMemoryPtr(pid, address, size, ptrData);
        }
    }

    public int CCAPIGetMemory(uint pid, ulong address, uint size, Span<byte> data)
    {
        fixed (byte* ptrData = data)
        {
            return CCAPIGetMemoryPtr(pid, address, size, ptrData);
        }
    }

    public int CCAPISetMemory(uint pid, ulong address, uint size, byte[] data)
    {
        fixed (byte* ptrData = data)
        {
            return CCAPISetMemoryPtr(pid, address, size, ptrData);
        }
    }

    public int CCAPISetMemory(uint pid, ulong address, uint size, ReadOnlySpan<byte> data)
    {
        fixed (byte* ptrData = data)
        {
            return CCAPISetMemoryPtr(pid, address, size, ptrData);
        }
    }

    public int CCAPIGetProcessCount(ref uint pidCount)
    {
        uint nPidCount = 0;
        int ret = CCAPIGetProcessListPtr(&nPidCount, (uint*)nuint.Zero);
        pidCount = nPidCount;
        return ret;

    }

    // Combine it with CCAPIGetProcessCount, this allows you to stackalloc the buffer, which is not possible
    // with CCAPIGetProcessListSafe
    public int CCAPIGetProcessList(ref uint[]? pids)
    {
        uint npids;
        if (pids != null)
        {
            fixed (uint* ptrPids = pids)
            {
                return CCAPIGetProcessListPtr(&npids, ptrPids);
            }
        }
        return -1;
    }

    public int CCAPIGetProcessList(Span<uint> pids)
    {
        uint npids;
        if (CCAPIGetProcessListPtr(&npids, (uint*)nuint.Zero) == 0)
        {
            fixed (uint* ptrPids = pids)
            {
                return CCAPIGetProcessListPtr(&npids, ptrPids);
            }
        }
        return -1;
    }

    public int CCAPIGetProcessListSafe(ref uint[]? pids)
    {
        uint npids;
        if (CCAPIGetProcessListPtr(&npids, (uint*)nuint.Zero) == 0)
        {
            if (pids == null || pids.Length != npids) pids = new uint[npids];
            fixed (uint* ptrPids = pids)
            {
                return CCAPIGetProcessListPtr(&npids, ptrPids);
            }
        }
        return -1;
    }

    public int CCAPIGetProcessName(uint pid, out string processName)
    {
        byte* ptrProcessName = stackalloc byte[512];

        if (CCAPIGetProcessNamePtr(pid, ptrProcessName) == 0)
        {
            processName = Encoding.ASCII.GetString(ptrProcessName, 512);
            return 0;
        }
        processName = string.Empty;
        return -1;
    }

    public enum TemperatureSystem
    {
        Celsius,
        Fahrenheit
    }

    public int CCAPIGetTemperature(ref int cell, ref int rsx, TemperatureSystem system = TemperatureSystem.Celsius)
    {
        int celltemp = 0, rsxtemp = 0;
        int ret = CCAPIGetTemperaturePtr(&celltemp, &rsxtemp);

        if (ret == 0)
        {
            if (system == TemperatureSystem.Fahrenheit)
            {
                cell = (celltemp * 9 / 5) + 32;
                rsx = (rsxtemp * 9 / 5) + 32;
                return ret;
            }
        }
        cell = celltemp;
        rsx = rsxtemp;
        return ret;
    }

    public int CCAPIShutdown(ShutdownMode mode)
    {
        return CCAPIShutdownPtr((int)mode);
    }

    public int CCAPIRingBuzzer(BuzzerType type)
    {
        return CCAPIRingBuzzerPtr((int)type);
    }

    public int CCAPISetConsoleLed(ColorLed color, StatusLed mode)
    {
        return CCAPISetConsoleLedPtr((int)color, (int)mode);
    }

    public int CCAPIGetFirmwareInfo(out string? firmwareVersion, out string? ccapiVersion, out string? cType)
    {
        uint fw, ccapi, ctype;
        int ret = CCAPIGetFirmwareInfoPtr(&fw, &ccapi, &ctype);
        if (ret == 0)
        {
            byte* ptrFw = stackalloc byte[4];
            byte* ptrCcapi = stackalloc byte[4];

            ptrFw[0] = (byte)(((fw >> 24) & 0xF) + 0x30);
            ptrFw[1] = 0x2E;
            ptrFw[2] = (byte)(((fw >> 16) & 0xF) + 0x30);
            ptrFw[3] = (byte)(((fw >> 12) & 0xF) + 0x30);
            firmwareVersion = Encoding.ASCII.GetString(ptrFw, 4);

            cType = Enum.GetName(typeof(ConsoleType), ctype);

            // Proper implementation needs to be done soon.
            ccapiVersion = Convert.ToString(ccapi, 16);

        }
        else
        {
            firmwareVersion = null;
            ccapiVersion = null;
            cType = null;
        }
        return ret;
    }

    public int CCAPIVshNotify(NotifyIcon icon, string message)
    {
        fixed (byte* ptrMessage = Encoding.ASCII.GetBytes(message))
        {
            return CCAPIVshNotifyPtr((int)icon, ptrMessage);
        }
    }

    public int CCAPIGetNumberOfConsoles()
    {
        return CCAPIGetNumberOfConsolesPtr();
    }

    public class ConsoleInfo
    {
        public string? Name, Ip;
    }

    public List<ConsoleInfo> CCAPIGetConsoleInfos()
    {
        int consoleCount = CCAPIGetNumberOfConsolesPtr();

        if (consoleCount > 0)
        {
            List<ConsoleInfo> consoleInfos = new List<ConsoleInfo>(consoleCount);
            ConsoleInfo consoleInfo = new ConsoleInfo();

            byte* ptrName = stackalloc byte[256];
            byte* ptrIp = stackalloc byte[256];

            for (int i = 0; i < consoleInfos.Count; i++)
            {
                CCAPIGetConsoleInfoPtr(i, ptrName, ptrIp);
                consoleInfo.Name = Encoding.ASCII.GetString(ptrName, 256);
                consoleInfo.Ip = Encoding.ASCII.GetString(ptrIp, 256);
                consoleInfos.Add(consoleInfo);
                NativeMemory.Clear(ptrName, 256);
                NativeMemory.Clear(ptrIp, 256);
            }
            return consoleInfos;
        }
        return new List<ConsoleInfo>();
    }

    public int CCAPIGetDllVersion()
    {
        return CCAPIGetDllVersionPtr();
    }

    private readonly Dictionary<byte, byte> dict = new Dictionary<byte, byte>()
    {
            { 0x30, 0x0 },
            { 0x31, 0x1 },
            { 0x32, 0x2 },
            { 0x33, 0x3 },
            { 0x34, 0x4 },
            { 0x35, 0x5 },
            { 0x36, 0x6 },
            { 0x37, 0x7 },
            { 0x38, 0x8 },
            { 0x39, 0x9 },
            { 0x41, 0xA },
            { 0x42, 0xB },
            { 0x43, 0xC },
            { 0x44, 0xD },
            { 0x45, 0xE },
            { 0x46, 0xF },
            { 0x61, 0xA },
            { 0x62, 0xB },
            { 0x63, 0xC },
            { 0x64, 0xD },
            { 0x65, 0xE },
            { 0x66, 0xF },
    };

    // This works only for even string lengths, odd implementation will follow very soon.
    private void HexStringToByteArray(string input, byte* ptrToTarget)
    {
        int len = input.Length;
        int j = 0;
        fixed (char* ptrToInput = input)
        {
            for (int i = 0; i < len; i += 2, j++)
            {
                byte bLeft = (byte)ptrToInput[i];
                byte bRight = (byte)ptrToInput[i + 1];

                bLeft = dict[bLeft];
                bRight = dict[bRight];

                ptrToTarget[j] = (byte)((bLeft << 4) | bRight);
            }
        }
    }
}

