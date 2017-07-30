# -*- encoding: utf-8 -*-
#
# For feedback or questions contact us at: github@eset.com
# https://github.com/eset/malware-research/
#
# Authors:
# Anton Cherepanov <cherepanov@eset.sk>
#
# Copyright (c) 2017, ESET, spol. s r.o.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the ESET, spol. s r. o.  nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL ESET spol. s r.o.  BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# OPC data structure definitions are based of work from The OPC Foundation,
# which have the following copyright notice:
# ========================================================================
# Copyright (c) 2005-2017 The OPC Foundation, Inc. All rights reserved.
#
# OPC Foundation MIT License 1.00
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
# The complete license agreement can be found here:
# http://opcfoundation.org/License/MIT/1.00/
# ========================================================================

from idc import *
import uuid

OPC_IDs = { 'LIBID_OPCCOMN': '{B28EEDB1-AC6F-11D1-84D5-00608CB8A7E9}',
            'LIBID_OpcDxLib': '{3CA18B30-1088-47D5-8952-0B12B027ED32}',
            'LIBID_OPCSEC': '{7AA83AFF-6C77-11D3-84F9-00008630A38B}',
            'LIBID_OPC_AE': '{65168844-5783-11D1-84A0-00608CB8A7E9}',
            'LIBID_OPC_BATCH': '{A8080DA4-E23E-11D2-AFA7-00C04F539421}',
            'LIBID_OpcCmdLib': '{3104B520-2016-442D-9696-1275DE978778}',
            'LIBID_OPCDA': '{3B540B51-0378-4551-ADCC-EA9B104302BF}',
            'LIBID_OpcEnumLib': '{13486D43-4821-11D2-A494-3CB306C10000}',
            'LIBID_OPCHDA': '{1F1217BA-DEE0-11D2-A5E5-000086339399}',
            'LIBID_OPCAutomation': '{28E68F91-8D75-11D1-8DC3-3C302A000000}',
            'CLSID_OpcServerList': '{13486D51-4821-11D2-A494-3CB306C10000}',
            'CLSID_OPCGroups': '{28E68F9E-8D75-11D1-8DC3-3C302A000000}',
            'CLSID_OPCGroup': '{28E68F9B-8D75-11D1-8DC3-3C302A000000}',
            'CLSID_OPCServer': '{28E68F9A-8D75-11D1-8DC3-3C302A000000}',
            'IID_CATID_OPCDAServer10': '{63D5F430-CFE4-11D1-B2C8-0060083BA1FB}',
            'IID_CATID_OPCDAServer20': '{63D5F432-CFE4-11D1-B2C8-0060083BA1FB}',
            'IID_CATID_OPCDAServer30': '{CC603642-66D7-48F1-B69A-B625E73652D7}',
            'IID_CATID_XMLDAServer10': '{3098EDA4-A006-48B2-A27F-247453959408}',
            'IID_CATID_OPCDXServer10': '{A0C85BB8-4161-4FD6-8655-BB584601C9E0}',
            'IID_CATID_OPCAEServer10': '{58E13251-AC87-11D1-84D5-00608CB8A7E9}',
            'IID_CATID_OPCHDAServer10': '{7DE5B060-E089-11D2-A5E6-000086339399}',
            'IID_CATID_OPCBatchServer10': '{A8080DA0-E23E-11D2-AFA7-00C04F539421}',
            'IID_CATID_OPCBatchServer20': '{843DE67B-B0C9-11D4-A0B7-000102A980B1}',
            'IID_CATID_OPCCMDServer10': '{2D869D5C-3B05-41FB-851A-642FB2B801A0}',
            'DIID_DIOPCServerEvent': '{28E68F93-8D75-11D1-8DC3-3C302A000000}',
            'DIID_DIOPCGroupEvent': '{28E68F97-8D75-11D1-8DC3-3C302A000000}',
            'DIID_DIOPCGroupsEvent': '{28E68F9D-8D75-11D1-8DC3-3C302A000000}',
            'IID_IOPCServerList': '{13486D50-4821-11D2-A4943CB306C10000}',
            'IID_IOPCServerList2': '{9DD0B56C-AD9E-43ee8305487F3188BF7A}',
            'IID_IOPCShutdown': '{F31DFDE1-07B6-11D2-B2D80060083BA1FB}',
            'IID_IOPCCommon': '{F31DFDE2-07B6-11D2-B2D80060083BA1FB}',
            'IID_IOPCEnumGUID': '{55C382C8-21C7-4e8896C1BECFB1E3F483}',
            'IID_IOPCServer': '{39C13A4D-011E-11D0-96750020AFD8ADB3}',
            'IID_IOPCServerPublicGroups': '{39C13A4E-011E-11D0-96750020AFD8ADB3}',
            'IID_IOPCBrowseServerAddressSpace': '{39C13A4F-011E-11D0-96750020AFD8ADB3}',
            'IID_IOPCGroupStateMgt': '{39C13A50-011E-11D0-96750020AFD8ADB3}',
            'IID_IOPCPublicGroupStateMgt': '{39C13A51-011E-11D0-96750020AFD8ADB3}',
            'IID_IOPCSyncIO': '{39C13A52-011E-11D0-96750020AFD8ADB3}',
            'IID_IOPCAsyncIO': '{39C13A53-011E-11D0-96750020AFD8ADB3}',
            'IID_IOPCItemMgt': '{39C13A54-011E-11D0-96750020AFD8ADB3}',
            'IID_IEnumOPCItemAttributes': '{39C13A55-011E-11D0-96750020AFD8ADB3}',
            'IID_IOPCDataCallback': '{39C13A70-011E-11D0-96750020AFD8ADB3}',
            'IID_IOPCAsyncIO2': '{39C13A71-011E-11D0-96750020AFD8ADB3}',
            'IID_IOPCItemProperties': '{39C13A72-011E-11D0-96750020AFD8ADB3}',
            'IID_IOPCItemDeadbandMgt': '{5946DA93-8B39-4EC8-AB3DAA73DF5BC86F}',
            'IID_IOPCItemSamplingMgt': '{3E22D313-F08B-41A5-86C895E95CB49FFC}',
            'IID_IOPCBrowse': '{39227004-A18F-4B57-8B0A5235670F4468}',
            'IID_IOPCItemIO': '{85C0B427-2893-4CBC-BD78E5FC5146F08F}',
            'IID_IOPCSyncIO2': '{730F5F0F-55B1-4C81-9E18FF8A0904E1FA}',
            'IID_IOPCAsyncIO3': '{0967B97B-36EF-423E-B6F86BFF1E40D39D}',
            'IID_IOPCGroupStateMgt2': '{8E368666-D72E-4F78-87ED647611C61C9F}',
            'IID_IOPCAutoServer': '{28E68F92-8D75-11D1-8DC3-3C302A000000}',
            'IID_OPCBrowser': '{28E68F94-8D75-11D1-8DC3-3C302A000000}',
            'IID_IOPCGroups': '{28E68F95-8D75-11D1-8DC3-3C302A000000}',
            'IID_IOPCGroup': '{28E68F96-8D75-11D1-8DC3-3C302A000000}',
            'IID_OPCItems': '{28E68F98-8D75-11D1-8DC3-3C302A000000}',
            'IID_OPCItem': '{28E68F99-8D75-11D1-8DC3-3C302A000000}',
            'IID_IOPCGroupsEvent': '{28E68F9C-8D75-11D1-8DC3-3C302A000000}',
            'IID_IOPCGroupEvent': '{28E68F90-8D75-11D1-8DC3-3C302A000000}',
            #-------------------- these GUIDs are also used -----------------------------
            'CLSID_ICatInformation': '{0002E005-0000-0000-C000-000000000046}',
            'IID_ICatInformation': '{0002E013-0000-0000-C000-000000000046}',
            'IID_IUnknown': '{00000000-0000-0000-C000-000000000046}',
            'IID_IClassFactory': '{00000001-0000-0000-C000-000000000046}',
            'IID_IConnectionPointContainer': '{B196B284-BAB4-101A-B69C-00AA00341D07}',
            }

LoadTil('mssdk')

id = GetStrucIdByName('IID')

if id == BADADDR:
    id = AddStrucEx(-1, 'IID', 0)
    id = GetStrucIdByName('IID')

    AddStrucMember(id, 'Data1', 0x0, FF_DWRD, -1, 4)
    AddStrucMember(id, 'Data2', 0x4, FF_WORD, -1, 2)
    AddStrucMember(id, 'Data3', 0x6, FF_WORD, -1, 2)
    AddStrucMember(id, 'Data4', 0x8, FF_BYTE, -1, 8)

for ID in OPC_IDs.keys():
    pattern = ' '.join(['{0:02X}'.format(ord(x)) for x in uuid.UUID(OPC_IDs[ID]).bytes_le])

    ea = FindBinary(MinEA(), SEARCH_DOWN, pattern)
    count = 0
    while ea != BADADDR:

        # let's re-check it because FindBinary can match only part of pattern
        if uuid.UUID(bytes_le=GetManyBytes(ea, 16)).hex != uuid.UUID(OPC_IDs[ID]).hex:
            ea = FindBinary(ea, SEARCH_DOWN | SEARCH_NEXT, pattern)
            continue

        if count == 0:
            name = ID
        else:
            name = '{0:s}_{1:02d}'.format(ID, count)

        MakeUnknown(ea, 16, DOUNK_SIMPLE)
        MakeName(ea, name)
        print'{0:08X} -> {1:s}'.format(ea, name)

        MakeStructEx(ea, -1, 'IID')
        count += 1

        ea = FindBinary(ea, SEARCH_DOWN | SEARCH_NEXT, pattern)


IOPCServerList_str = """
    struct IOPCServerList
    {
        struct IOPCServerListVtbl *lpVtbl;
    };
"""
SetLocalType(-1, IOPCServerList_str, 0)
Til2Idb(-1, "IOPCServerList")

IOPCServerListVtbl_str = """
    struct IOPCServerListVtbl
    {
        HRESULT (__stdcall *QueryInterface)(IOPCServerList * This, IID * riid, void **ppvObject);
        ULONG (__stdcall *AddRef)(IOPCServerList * This);
        ULONG (__stdcall *Release)(IOPCServerList * This);
        HRESULT (__stdcall *EnumClassesOfCategories)(IOPCServerList * This, ULONG cImplemented, CATID rgcatidImpl, ULONG cRequired, CATID rgcatidReq, IEnumGUID **ppenumClsid);
        HRESULT (__stdcall *GetClassDetails)(IOPCServerList * This, CLSID * clsid, LPOLESTR *ppszProgID, LPOLESTR *ppszUserType);
        HRESULT (__stdcall *CLSIDFromProgID)(IOPCServerList * This, LPCOLESTR szProgId, LPCLSID clsid);
    };
"""
SetLocalType(-1, IOPCServerListVtbl_str, 0)
Til2Idb(-1, "IOPCServerListVtbl")

IOPCShutdown_str = """
    struct IOPCShutdown
    {
        struct IOPCShutdownVtbl *lpVtbl;
    };
"""
SetLocalType(-1,IOPCShutdown_str, 0)
Til2Idb(-1, "IOPCShutdown")

IOPCShutdownVtbl_str = """
    struct IOPCShutdownVtbl
    {
        HRESULT (__stdcall *QueryInterface)(IOPCShutdown * This, IID * riid, void **ppvObject);
        ULONG (__stdcall *AddRef)(IOPCShutdown * This);
        ULONG (__stdcall *Release)(IOPCShutdown * This);
        HRESULT (__stdcall *ShutdownRequest)(IOPCShutdown * This, LPCWSTR szReason);
    };
"""
SetLocalType(-1, IOPCShutdownVtbl_str, 0)
Til2Idb(-1, "IOPCShutdownVtbl")

IOPCCommon_str = """
    struct IOPCCommon
    {
        struct IOPCCommonVtbl *lpVtbl;
    };
"""
SetLocalType(-1, IOPCCommon_str, 0)
Til2Idb(-1, "IOPCCommon")

IOPCCommonVtbl_str = """
    struct IOPCCommonVtbl
    {
        HRESULT (__stdcall *QueryInterface)(IOPCCommon * This, IID * riid, void **ppvObject);
        ULONG (__stdcall *AddRef)(IOPCCommon * This);
        ULONG (__stdcall *Release)(IOPCCommon * This);
        HRESULT (__stdcall *SetLocaleID)(IOPCCommon * This, LCID dwLcid);
        HRESULT (__stdcall *GetLocaleID)(IOPCCommon * This, LCID *pdwLcid);
        HRESULT (__stdcall *QueryAvailableLocaleIDs)(IOPCCommon * This, DWORD *pdwCount, LCID **pdwLcid);
        HRESULT (__stdcall *GetErrorString)(IOPCCommon * This, HRESULT dwError, LPWSTR *ppString);
        HRESULT (__stdcall *SetClientName)(IOPCCommon * This, LPCWSTR szName);
    };
"""
SetLocalType(-1, IOPCCommonVtbl_str, 0)
Til2Idb(-1, "IOPCCommonVtbl")

IOPCEnumGUID_str = """
    struct IOPCEnumGUID
    {
        struct IOPCEnumGUIDVtbl *lpVtbl;
    };
"""
SetLocalType(-1, IOPCEnumGUID_str, 0)
Til2Idb(-1, "IOPCEnumGUID")

IOPCEnumGUIDVtbl_str = """
    struct IOPCEnumGUIDVtbl
    {
        HRESULT (__stdcall *QueryInterface)(IOPCEnumGUID * This, IID * riid, void **ppvObject);
        ULONG (__stdcall *AddRef)(IOPCEnumGUID * This);
        ULONG (__stdcall *Release)(IOPCEnumGUID * This);
        HRESULT (__stdcall *Next)(IOPCEnumGUID * This, ULONG celt, GUID *rgelt, ULONG *pceltFetched);
        HRESULT (__stdcall *Skip)(IOPCEnumGUID * This, ULONG celt);
        HRESULT (__stdcall *Reset)(IOPCEnumGUID * This);
        HRESULT (__stdcall *Clone)(IOPCEnumGUID * This, IOPCEnumGUID **ppenum);
    };
"""
SetLocalType(-1, IOPCEnumGUIDVtbl_str, 0)
Til2Idb(-1, "IOPCEnumGUIDVtbl")

CATID_OPCDAServer10_str = """
    struct CATID_OPCDAServer10
    {
        struct CATID_OPCDAServer10Vtbl *lpVtbl;
    };
"""
SetLocalType(-1, CATID_OPCDAServer10_str, 0)
Til2Idb(-1, "CATID_OPCDAServer10")

CATID_OPCDAServer10Vtbl_str = """
    struct CATID_OPCDAServer10Vtbl
    {
        HRESULT (__stdcall *QueryInterface)(CATID_OPCDAServer10 * This, IID * riid, void **ppvObject);
        ULONG (__stdcall *AddRef)(CATID_OPCDAServer10 * This);
        ULONG (__stdcall *Release)(CATID_OPCDAServer10 * This);
    };
"""
SetLocalType(-1, CATID_OPCDAServer10Vtbl_str, 0)
Til2Idb(-1, "CATID_OPCDAServer10Vtbl")

CATID_OPCDAServer20_str = """
    struct CATID_OPCDAServer20
    {
        struct CATID_OPCDAServer20Vtbl *lpVtbl;
    };
"""
SetLocalType(-1, CATID_OPCDAServer20_str, 0)
Til2Idb(-1, "CATID_OPCDAServer20")

CATID_OPCDAServer20Vtbl_str = """
    struct CATID_OPCDAServer20Vtbl
    {
        HRESULT (__stdcall *QueryInterface)(CATID_OPCDAServer20 * This, IID * riid, void **ppvObject);
        ULONG (__stdcall *AddRef)(CATID_OPCDAServer20 * This);
        ULONG (__stdcall *Release)(CATID_OPCDAServer20 * This);
    };
"""
SetLocalType(-1, CATID_OPCDAServer20Vtbl_str, 0)
Til2Idb(-1, "CATID_OPCDAServer20Vtbl")

CATID_OPCDAServer30_str = """
    struct CATID_OPCDAServer30
    {
        struct CATID_OPCDAServer30Vtbl *lpVtbl;
    };
"""
SetLocalType(-1, CATID_OPCDAServer30_str, 0)
Til2Idb(-1, "CATID_OPCDAServer30")

CATID_OPCDAServer30Vtbl_str = """
    struct CATID_OPCDAServer30Vtbl
    {
        HRESULT (__stdcall *QueryInterface)(CATID_OPCDAServer30 * This, IID * riid, void **ppvObject);
        ULONG (__stdcall *AddRef)(CATID_OPCDAServer30 * This);
        ULONG (__stdcall *Release)(CATID_OPCDAServer30 * This);
    };
"""
SetLocalType(-1, CATID_OPCDAServer30Vtbl_str, 0)
Til2Idb(-1, "CATID_OPCDAServer30Vtbl")

CATID_XMLDAServer10_str = """
    struct CATID_XMLDAServer10
    {
        struct CATID_XMLDAServer10Vtbl *lpVtbl;
    };
"""
SetLocalType(-1, CATID_XMLDAServer10_str, 0)
Til2Idb(-1, "CATID_XMLDAServer10")

CATID_XMLDAServer10Vtbl_str = """
    struct CATID_XMLDAServer10Vtbl
    {
        HRESULT (__stdcall *QueryInterface)(CATID_XMLDAServer10 * This, IID * riid, void **ppvObject);
        ULONG (__stdcall *AddRef)(CATID_XMLDAServer10 * This);
        ULONG (__stdcall *Release)(CATID_XMLDAServer10 * This);
    };
"""
SetLocalType(-1, CATID_XMLDAServer10Vtbl_str, 0)
Til2Idb(-1, "CATID_XMLDAServer10Vtbl")

SetLocalType(-1, 'typedef DWORD OPCHANDLE;', 0)
Til2Idb(-1, "OPCHANDLE")

enum_id = AddEnum(-1, 'OPCDATASOURCE', 0)
AddConstEx(enum_id, 'OPC_DS_CACHE', 1, -1)
AddConstEx(enum_id, 'OPC_DS_DEVICE', 2, -1)

enum_id = AddEnum(-1, 'OPCBROWSETYPE', 0)
AddConstEx(enum_id, 'OPC_BRANCH', 1, -1)
AddConstEx(enum_id, 'OPC_LEAF', 2, -1)
AddConstEx(enum_id, 'OPC_FLAT', 3, -1)

enum_id = AddEnum(-1, 'OPCNAMESPACETYPE', 0)
AddConstEx(enum_id, 'OPC_NS_HIERARCHIAL', 1, -1)
AddConstEx(enum_id, 'OPC_NS_FLAT', 2, -1)

enum_id = AddEnum(-1, 'OPCBROWSEDIRECTION', 0)
AddConstEx(enum_id, 'OPC_BROWSE_UP', 1, -1)
AddConstEx(enum_id, 'OPC_BROWSE_DOWN', 2, -1)
AddConstEx(enum_id, 'OPC_BROWSE_TO', 3, -1)

enum_id = AddEnum(-1, 'OPCEUTYPE', 0)
AddConstEx(enum_id, 'OPC_NOENUM', 1, -1)
AddConstEx(enum_id, 'OPC_ANALOG', 2, -1)
AddConstEx(enum_id, 'OPC_ENUMERATED', 3, -1)

enum_id = AddEnum(-1, 'OPCSERVERSTATE', 0)
AddConstEx(enum_id, 'OPC_STATUS_RUNNING', 1, -1)
AddConstEx(enum_id, 'OPC_STATUS_FAILED', 2, -1)
AddConstEx(enum_id, 'OPC_STATUS_NOCONFIG', 3, -1)
AddConstEx(enum_id, 'OPC_STATUS_SUSPENDED', 4, -1)
AddConstEx(enum_id, 'OPC_STATUS_TEST', 5, -1)
AddConstEx(enum_id, 'OPC_STATUS_COMM_FAULT', 6, -1)

enum_id = AddEnum(-1, 'OPCENUMSCOPE', 0)
AddConstEx(enum_id, 'OPC_ENUM_PRIVATE_CONNECTIONS', 1, -1)
AddConstEx(enum_id, 'OPC_ENUM_PUBLIC_CONNECTIONS', 2, -1)
AddConstEx(enum_id, 'OPC_ENUM_ALL_CONNECTIONS', 3, -1)
AddConstEx(enum_id, 'OPC_ENUM_PRIVATE', 4, -1)
AddConstEx(enum_id, 'OPC_ENUM_PUBLIC', 5, -1)
AddConstEx(enum_id, 'OPC_ENUM_ALL', 6, -1)

OPCGROUPHEADER_str = """
    struct OPCGROUPHEADER
    {
        DWORD dwSize;
        DWORD dwItemCount;
        OPCHANDLE hClientGroup;
        DWORD dwTransactionID;
        HRESULT hrStatus;
    };
"""
SetLocalType(-1, OPCGROUPHEADER_str, 0)
Til2Idb(-1, "OPCGROUPHEADER")

OPCITEMHEADER1_str = """
    struct OPCITEMHEADER1
    {
        OPCHANDLE hClient;
        DWORD dwValueOffset;
        WORD wQuality;
        WORD wReserved;
        FILETIME ftTimeStampItem;
    };
"""
SetLocalType(-1, OPCITEMHEADER1_str, 0)
Til2Idb(-1, "OPCITEMHEADER1")

OPCITEMHEADER2_str = """
    struct OPCITEMHEADER2
    {
        OPCHANDLE hClient;
        DWORD dwValueOffset;
        WORD wQuality;
        WORD wReserved;
    };
"""
SetLocalType(-1, OPCITEMHEADER2_str, 0)
Til2Idb(-1, "OPCITEMHEADER2")

OPCGROUPHEADERWRITE_str = """
    struct OPCGROUPHEADERWRITE
    {
        DWORD dwItemCount;
        OPCHANDLE hClientGroup;
        DWORD dwTransactionID;
        HRESULT hrStatus;
    };
"""
SetLocalType(-1, OPCGROUPHEADERWRITE_str, 0)
Til2Idb(-1, "OPCGROUPHEADERWRITE")

OPCITEMHEADERWRITE_str = """
    struct OPCITEMHEADERWRITE
    {
        OPCHANDLE hClient;
        HRESULT dwError;
    };
"""
SetLocalType(-1, OPCITEMHEADERWRITE_str, 0)
Til2Idb(-1, "OPCITEMHEADERWRITE")

OPCITEMSTATE_str = """
    struct OPCITEMSTATE
    {
        OPCHANDLE hClient;
        FILETIME ftTimeStamp;
        WORD wQuality;
        WORD wReserved;
        VARIANT vDataValue;
    };
"""
SetLocalType(-1, OPCITEMSTATE_str, 0)
Til2Idb(-1, "OPCITEMSTATE")

OPCSERVERSTATUS_str = """
    struct OPCSERVERSTATUS
    {
        FILETIME ftStartTime;
        FILETIME ftCurrentTime;
        FILETIME ftLastUpdateTime;
        OPCSERVERSTATE dwServerState;
        DWORD dwGroupCount;
        DWORD dwBandWidth;
        WORD wMajorVersion;
        WORD wMinorVersion;
        WORD wBuildNumber;
        WORD wReserved;
        LPWSTR szVendorInfo;
    };
"""
SetLocalType(-1, OPCSERVERSTATUS_str, 0)
Til2Idb(-1, "OPCSERVERSTATUS")

OPCITEMDEF_str = """
    struct OPCITEMDEF
    {
        LPWSTR szAccessPath;
        LPWSTR szItemID;
        BOOL bActive;
        OPCHANDLE hClient;
        DWORD dwBlobSize;
        BYTE *pBlob;
        VARTYPE vtRequestedDataType;
        WORD wReserved;
    };
"""
SetLocalType(-1, OPCITEMDEF_str, 0)
Til2Idb(-1, "OPCITEMDEF")

OPCITEMATTRIBUTES_str = """
    struct OPCITEMATTRIBUTES
    {
        LPWSTR szAccessPath;
        LPWSTR szItemID;
        BOOL bActive;
        OPCHANDLE hClient;
        OPCHANDLE hServer;
        DWORD dwAccessRights;
        DWORD dwBlobSize;
        BYTE *pBlob;
        VARTYPE vtRequestedDataType;
        VARTYPE vtCanonicalDataType;
        OPCEUTYPE dwEUType;
        VARIANT vEUInfo;
    };
"""
SetLocalType(-1, OPCITEMATTRIBUTES_str, 0)
Til2Idb(-1, "OPCITEMATTRIBUTES")

OPCITEMRESULT_str = """
    struct OPCITEMRESULT
    {
        OPCHANDLE hServer;
        VARTYPE vtCanonicalDataType;
        WORD wReserved;
        DWORD dwAccessRights;
        DWORD dwBlobSize;
        BYTE *pBlob;
    };
"""
SetLocalType(-1, OPCITEMRESULT_str, 0)
Til2Idb(-1, "OPCITEMRESULT")

OPCITEMPROPERTY_str = """
    struct OPCITEMPROPERTY
    {
        VARTYPE vtDataType;
        WORD wReserved;
        DWORD dwPropertyID;
        LPWSTR szItemID;
        LPWSTR szDescription;
        VARIANT vValue;
        HRESULT hrErrorID;
        DWORD dwReserved;
    };
"""
SetLocalType(-1, OPCITEMPROPERTY_str, 0)
Til2Idb(-1, "OPCITEMPROPERTY")

OPCITEMPROPERTIES_str = """
    struct OPCITEMPROPERTIES
    {
        HRESULT hrErrorID;
        DWORD dwNumProperties;
        OPCITEMPROPERTY *pItemProperties;
        DWORD dwReserved;
    };
"""
SetLocalType(-1, OPCITEMPROPERTIES_str, 0)
Til2Idb(-1, "OPCITEMPROPERTIES")

OPCBROWSEELEMENT_str = """
    struct OPCBROWSEELEMENT
    {
        LPWSTR szName;
        LPWSTR szItemID;
        DWORD dwFlagValue;
        DWORD dwReserved;
        OPCITEMPROPERTIES ItemProperties;
    };
"""
SetLocalType(-1, OPCBROWSEELEMENT_str, 0)
Til2Idb(-1, "OPCBROWSEELEMENT")

OPCITEMVQT_str = """
    struct OPCITEMVQT
    {
        VARIANT vDataValue;
        BOOL bQualitySpecified;
        WORD wQuality;
        WORD wReserved;
        BOOL bTimeStampSpecified;
        DWORD dwReserved;
        FILETIME ftTimeStamp;
    };
"""
SetLocalType(-1, OPCITEMVQT_str, 0)
Til2Idb(-1, "OPCITEMVQT")

enum_id = AddEnum(-1, 'OPCBROWSEFILTER', 0)
AddConstEx(enum_id, 'OPC_BROWSE_FILTER_ALL', 1, -1)
AddConstEx(enum_id, 'OPC_BROWSE_FILTER_BRANCHES', 2, -1)
AddConstEx(enum_id, 'OPC_BROWSE_FILTER_ITEMS', 3, -1)

IOPCServer_str = """
    struct IOPCServer
    {
        struct IOPCServerVtbl *lpVtbl;
    };
"""
SetLocalType(-1, IOPCServer_str, 0)
Til2Idb(-1, "IOPCServer")

IOPCServerVtbl_str = """
    struct IOPCServerVtbl
    {
        HRESULT (__stdcall *QueryInterface)(IOPCServer * This, IID * riid, void **ppvObject);
        ULONG (__stdcall *AddRef)(IOPCServer * This);
        ULONG (__stdcall *Release)(IOPCServer * This);
        HRESULT (__stdcall *AddGroup)(IOPCServer * This, LPCWSTR szName, BOOL bActive, DWORD dwRequestedUpdateRate, OPCHANDLE hClientGroup, LONG *pTimeBias, FLOAT *pPercentDeadband, DWORD dwLCID, OPCHANDLE *phServerGroup, DWORD *pRevisedUpdateRate, IID * riid, LPUNKNOWN *ppUnk);
        HRESULT (__stdcall *GetErrorString)(IOPCServer * This, HRESULT dwError, LCID dwLocale, LPWSTR *ppString);
        HRESULT (__stdcall *GetGroupByName)(IOPCServer * This, LPCWSTR szName, IID * riid, LPUNKNOWN *ppUnk);
        HRESULT (__stdcall *GetStatus)(IOPCServer * This, OPCSERVERSTATUS **ppServerStatus);
        HRESULT (__stdcall *RemoveGroup)(IOPCServer * This, OPCHANDLE hServerGroup, BOOL bForce);
        HRESULT (__stdcall *CreateGroupEnumerator)(IOPCServer * This, OPCENUMSCOPE dwScope, IID * riid, LPUNKNOWN *ppUnk);
    };
"""
SetLocalType(-1, IOPCServerVtbl_str, 0)
Til2Idb(-1, "IOPCServerVtbl")

IOPCServerPublicGroups_str = """
    struct IOPCServerPublicGroups
    {
        struct IOPCServerPublicGroupsVtbl *lpVtbl;
    };
"""
SetLocalType(-1, IOPCServerPublicGroups_str, 0)
Til2Idb(-1, "IOPCServerPublicGroups")

IOPCServerPublicGroupsVtbl_str = """
    struct IOPCServerPublicGroupsVtbl
    {
        HRESULT (__stdcall *QueryInterface)(IOPCServerPublicGroups * This, IID * riid, void **ppvObject);
        ULONG (__stdcall *AddRef)(IOPCServerPublicGroups * This);
        ULONG (__stdcall *Release)(IOPCServerPublicGroups * This);
        HRESULT (__stdcall *GetPublicGroupByName)(IOPCServerPublicGroups * This, LPCWSTR szName, IID * riid, LPUNKNOWN *ppUnk);
        HRESULT (__stdcall *RemovePublicGroup)(IOPCServerPublicGroups * This, OPCHANDLE hServerGroup, BOOL bForce);
    };
"""

SetLocalType(-1, IOPCServerPublicGroupsVtbl_str, 0)
Til2Idb(-1, "IOPCServerPublicGroupsVtbl")

IOPCBrowseServerAddressSpace_str = """
    struct IOPCBrowseServerAddressSpace
    {
        struct IOPCBrowseServerAddressSpaceVtbl *lpVtbl;
    };
"""
SetLocalType(-1, IOPCBrowseServerAddressSpace_str, 0)
Til2Idb(-1, "IOPCBrowseServerAddressSpace")

IOPCBrowseServerAddressSpaceVtbl_str = """
    struct IOPCBrowseServerAddressSpaceVtbl
    {
        HRESULT (__stdcall *QueryInterface)(IOPCBrowseServerAddressSpace * This, IID * riid, void **ppvObject);
        ULONG (__stdcall *AddRef)(IOPCBrowseServerAddressSpace * This);
        ULONG (__stdcall *Release)(IOPCBrowseServerAddressSpace * This);
        HRESULT (__stdcall *QueryOrganization)(IOPCBrowseServerAddressSpace * This, OPCNAMESPACETYPE *pNameSpaceType);
        HRESULT (__stdcall *ChangeBrowsePosition)(IOPCBrowseServerAddressSpace * This, OPCBROWSEDIRECTION dwBrowseDirection, LPCWSTR szString);
        HRESULT (__stdcall *BrowseOPCItemIDs)(IOPCBrowseServerAddressSpace * This, OPCBROWSETYPE dwBrowseFilterType, LPCWSTR szFilterCriteria, VARTYPE vtDataTypeFilter, DWORD dwAccessRightsFilter, LPENUMSTRING *ppIEnumString);
        HRESULT (__stdcall *GetItemID)(IOPCBrowseServerAddressSpace * This, LPWSTR szItemDataID, LPWSTR *szItemID);
        HRESULT (__stdcall *BrowseAccessPaths)(IOPCBrowseServerAddressSpace * This, LPCWSTR szItemID, LPENUMSTRING *ppIEnumString);
    };
"""

SetLocalType(-1, IOPCBrowseServerAddressSpaceVtbl_str, 0)
Til2Idb(-1, "IOPCBrowseServerAddressSpaceVtbl")

IOPCGroupStateMgt_str = """
    struct IOPCGroupStateMgt
    {
        struct IOPCGroupStateMgtVtbl *lpVtbl;
    };
"""
SetLocalType(-1, IOPCGroupStateMgt_str, 0)
Til2Idb(-1, "IOPCGroupStateMgt")

IOPCGroupStateMgtVtbl_str = """
    struct IOPCGroupStateMgtVtbl
    {
        HRESULT (__stdcall *QueryInterface)(IOPCGroupStateMgt * This, IID * riid, void **ppvObject);
        ULONG (__stdcall *AddRef)(IOPCGroupStateMgt * This);
        ULONG (__stdcall *Release)(IOPCGroupStateMgt * This);
        HRESULT (__stdcall *GetState)(IOPCGroupStateMgt * This, DWORD *pUpdateRate, BOOL *pActive, LPWSTR *ppName, LONG *pTimeBias, FLOAT *pPercentDeadband, DWORD *pLCID, OPCHANDLE *phClientGroup, OPCHANDLE *phServerGroup);
        HRESULT (__stdcall *SetState)(IOPCGroupStateMgt * This, DWORD *pRequestedUpdateRate, DWORD *pRevisedUpdateRate, BOOL *pActive, LONG *pTimeBias, FLOAT *pPercentDeadband, DWORD *pLCID, OPCHANDLE *phClientGroup);
        HRESULT (__stdcall *SetName)(IOPCGroupStateMgt * This, LPCWSTR szName);
        HRESULT (__stdcall *CloneGroup)(IOPCGroupStateMgt * This, LPCWSTR szName, IID * riid, LPUNKNOWN *ppUnk);
    };
"""

SetLocalType(-1, IOPCGroupStateMgtVtbl_str, 0)
Til2Idb(-1, "IOPCGroupStateMgtVtbl")

IIOPCSyncIO_str = """
    struct IOPCSyncIO
    {
        struct IOPCSyncIOVtbl *lpVtbl;
    };
"""
SetLocalType(-1, IIOPCSyncIO_str, 0)
Til2Idb(-1, "IOPCSyncIO")

IOPCSyncIOVtbl_str = """
    struct IOPCSyncIOVtbl
    {
        HRESULT (__stdcall *QueryInterface)(IOPCSyncIO * This, IID * riid, void **ppvObject);
        ULONG (__stdcall *AddRef)(IOPCSyncIO * This);
        ULONG (__stdcall *Release)(IOPCSyncIO * This);
        HRESULT (__stdcall *Read)(IOPCSyncIO * This, OPCDATASOURCE dwSource, DWORD dwCount, OPCHANDLE *phServer, OPCITEMSTATE **ppItemValues, HRESULT **ppErrors);
        HRESULT (__stdcall *Write)(IOPCSyncIO * This, DWORD dwCount, OPCHANDLE *phServer, VARIANT *pItemValues, HRESULT **ppErrors);
    };
"""

SetLocalType(-1, IOPCSyncIOVtbl_str, 0)
Til2Idb(-1, "IOPCSyncIOVtbl")

IOPCAsyncIO_str = """
    struct IOPCAsyncIO
    {
        struct IOPCAsyncIOVtbl *lpVtbl;
    };
"""
SetLocalType(-1, IOPCAsyncIO_str, 0)
Til2Idb(-1, "IOPCAsyncIO")

IOPCAsyncIOVtbl_str = """
    struct IOPCAsyncIOVtbl
    {
        HRESULT (__stdcall *QueryInterface)(IOPCAsyncIO * This, IID * riid, void **ppvObject);
        ULONG (__stdcall *AddRef)(IOPCAsyncIO * This);
        ULONG (__stdcall *Release)(IOPCAsyncIO * This);
        HRESULT (__stdcall *Read)(IOPCAsyncIO * This, DWORD dwConnection, OPCDATASOURCE dwSource, DWORD dwCount, OPCHANDLE *phServer, DWORD *pTransactionID, HRESULT **ppErrors);
        HRESULT (__stdcall *Write)(IOPCAsyncIO * This, DWORD dwConnection, DWORD dwCount, OPCHANDLE *phServer, VARIANT *pItemValues, DWORD *pTransactionID, HRESULT **ppErrors);
        HRESULT (__stdcall *Refresh)(IOPCAsyncIO * This, DWORD dwConnection, OPCDATASOURCE dwSource, DWORD *pTransactionID);
        HRESULT (__stdcall *Cancel)(IOPCAsyncIO * This, DWORD dwTransactionID);
    };
"""

SetLocalType(-1, IOPCAsyncIOVtbl_str, 0)
Til2Idb(-1, "IOPCAsyncIOVtbl")

IOPCItemMgt_str = """
    struct IOPCItemMgt
    {
        struct IOPCItemMgtVtbl *lpVtbl;
    };
"""
SetLocalType(-1, IOPCItemMgt_str, 0)
Til2Idb(-1, "IOPCItemMgt")

IOPCItemMgtVtbl_str = """
    struct IOPCItemMgtVtbl
    {
        HRESULT (__stdcall *QueryInterface)(IOPCItemMgt * This, IID * riid, void **ppvObject);
        ULONG (__stdcall *AddRef)(IOPCItemMgt * This);
        ULONG (__stdcall *Release)(IOPCItemMgt * This);
        HRESULT (__stdcall *AddItems)(IOPCItemMgt * This, DWORD dwCount, OPCITEMDEF *pItemArray, OPCITEMRESULT **ppAddResults, HRESULT **ppErrors);
        HRESULT (__stdcall *ValidateItems)(IOPCItemMgt * This, DWORD dwCount, OPCITEMDEF *pItemArray, BOOL bBlobUpdate, OPCITEMRESULT **ppValidationResults, HRESULT **ppErrors);
        HRESULT (__stdcall *RemoveItems)(IOPCItemMgt * This, DWORD dwCount, OPCHANDLE *phServer, HRESULT **ppErrors);
        HRESULT (__stdcall *SetActiveState)(IOPCItemMgt * This, DWORD dwCount, OPCHANDLE *phServer, BOOL bActive, HRESULT **ppErrors);
        HRESULT (__stdcall *SetClientHandles)(IOPCItemMgt * This, DWORD dwCount, OPCHANDLE *phServer, OPCHANDLE *phClient, HRESULT **ppErrors);
        HRESULT (__stdcall *SetDatatypes)(IOPCItemMgt * This, DWORD dwCount, OPCHANDLE *phServer, VARTYPE *pRequestedDatatypes, HRESULT **ppErrors);
        HRESULT (__stdcall *CreateEnumerator)(IOPCItemMgt * This, IID * riid, LPUNKNOWN *ppUnk);
    };
"""

SetLocalType(-1, IOPCItemMgtVtbl_str, 0)
Til2Idb(-1, "IOPCItemMgtVtbl")

IEnumOPCItemAttributes_str = """
    struct IEnumOPCItemAttributes
    {
        struct IEnumOPCItemAttributesVtbl *lpVtbl;
    };
"""
SetLocalType(-1, IEnumOPCItemAttributes_str, 0)
Til2Idb(-1, "IEnumOPCItemAttributes")

IEnumOPCItemAttributesVtbl_str = """
    struct IEnumOPCItemAttributesVtbl
    {
        HRESULT (__stdcall *QueryInterface)(IEnumOPCItemAttributes * This, IID * riid, void **ppvObject);
        ULONG (__stdcall *AddRef)(IEnumOPCItemAttributes * This);
        ULONG (__stdcall *Release)(IEnumOPCItemAttributes * This);
        HRESULT (__stdcall *Next)(IEnumOPCItemAttributes * This, ULONG celt, OPCITEMATTRIBUTES **ppItemArray, ULONG *pceltFetched);
        HRESULT (__stdcall *Skip)(IEnumOPCItemAttributes * This, ULONG celt);
        HRESULT (__stdcall *Reset)(IEnumOPCItemAttributes * This);
        HRESULT (__stdcall *Clone)(IEnumOPCItemAttributes * This, IEnumOPCItemAttributes **ppEnumItemAttributes);
    };
"""

SetLocalType(-1, IEnumOPCItemAttributesVtbl_str, 0)
Til2Idb(-1, "IEnumOPCItemAttributesVtbl")

IOPCDataCallback_str = """
    struct IOPCDataCallback
    {
        struct IOPCDataCallbackVtbl *lpVtbl;
    };
"""
SetLocalType(-1, IOPCDataCallback_str, 0)
Til2Idb(-1, "IOPCDataCallback")

IOPCDataCallbackVtbl_str = """
    struct IOPCDataCallbackVtbl
    {
        HRESULT (__stdcall *QueryInterface)(IOPCDataCallback * This, IID * riid, void **ppvObject);
        ULONG (__stdcall *AddRef)(IOPCDataCallback * This);
        ULONG (__stdcall *Release)(IOPCDataCallback * This);
        HRESULT (__stdcall *OnDataChange)(IOPCDataCallback * This, DWORD dwTransid, OPCHANDLE hGroup, HRESULT hrMasterquality, HRESULT hrMastererror, DWORD dwCount, OPCHANDLE *phClientItems, VARIANT *pvValues, WORD *pwQualities, FILETIME *pftTimeStamps, HRESULT *pErrors);
        HRESULT (__stdcall *OnReadComplete)(IOPCDataCallback * This, DWORD dwTransid, OPCHANDLE hGroup, HRESULT hrMasterquality, HRESULT hrMastererror, DWORD dwCount, OPCHANDLE *phClientItems, VARIANT *pvValues, WORD *pwQualities, FILETIME *pftTimeStamps, HRESULT *pErrors);
        HRESULT (__stdcall *OnWriteComplete )(IOPCDataCallback * This, DWORD dwTransid, OPCHANDLE hGroup, HRESULT hrMastererr, DWORD dwCount, OPCHANDLE *pClienthandles, HRESULT *pErrors);
        HRESULT ( __stdcall *OnCancelComplete )(IOPCDataCallback * This, DWORD dwTransid, OPCHANDLE hGroup);
    };
"""

SetLocalType(-1, IOPCDataCallbackVtbl_str, 0)
Til2Idb(-1, "IOPCDataCallbackVtbl")

IOPCAsyncIO2_str = """
    struct IOPCAsyncIO2
    {
        struct IOPCAsyncIO2Vtbl *lpVtbl;
    };
"""
SetLocalType(-1, IOPCAsyncIO2_str, 0)
Til2Idb(-1, "IOPCAsyncIO2")

IOPCAsyncIO2Vtbl_str = """
    struct IOPCAsyncIO2Vtbl
    {
        HRESULT (__stdcall *QueryInterface)(IOPCAsyncIO2 * This, IID * riid, void **ppvObject);
        ULONG (__stdcall *AddRef)(IOPCAsyncIO2 * This);
        ULONG (__stdcall *Release)(IOPCAsyncIO2 * This);
        HRESULT (__stdcall *Read)(IOPCAsyncIO2 * This, DWORD dwCount, OPCHANDLE *phServer, DWORD dwTransactionID, DWORD *pdwCancelID, HRESULT **ppErrors);
        HRESULT (__stdcall *Write)(IOPCAsyncIO2 * This, DWORD dwCount, OPCHANDLE *phServer, VARIANT *pItemValues, DWORD dwTransactionID, DWORD *pdwCancelID, HRESULT **ppErrors);
        HRESULT (__stdcall *Refresh2)(IOPCAsyncIO2 * This, OPCDATASOURCE dwSource, DWORD dwTransactionID, DWORD *pdwCancelID);
        HRESULT (__stdcall *Cancel2)(IOPCAsyncIO2 * This, DWORD dwCancelID);
        HRESULT (__stdcall *SetEnable)(IOPCAsyncIO2 * This, BOOL bEnable);
        HRESULT (__stdcall *GetEnable)(IOPCAsyncIO2 * This, BOOL *pbEnable);
    };
"""

SetLocalType(-1, IOPCAsyncIO2Vtbl_str, 0)
Til2Idb(-1, "IOPCAsyncIO2Vtbl")

IOPCItemProperties_str = """
    struct IOPCItemProperties
    {
        struct IOPCItemPropertiesVtbl *lpVtbl;
    };
"""
SetLocalType(-1, IOPCItemProperties_str, 0)
Til2Idb(-1, "IOPCItemProperties")

IOPCItemPropertiesVtbl_str = """
    struct IOPCItemPropertiesVtbl
    {
        HRESULT (__stdcall *QueryInterface)(IOPCItemProperties * This, IID * riid, void **ppvObject);
        ULONG (__stdcall *AddRef)(IOPCItemProperties * This);
        ULONG (__stdcall *Release)(IOPCItemProperties * This);
        HRESULT (__stdcall *QueryAvailableProperties)(IOPCItemProperties * This, LPWSTR szItemID, DWORD *pdwCount, DWORD **ppPropertyIDs, LPWSTR **ppDescriptions, VARTYPE **ppvtDataTypes);
        HRESULT (__stdcall *GetItemProperties)(IOPCItemProperties * This, LPWSTR szItemID, DWORD dwCount, DWORD *pdwPropertyIDs, VARIANT **ppvData, HRESULT **ppErrors);
        HRESULT (__stdcall *LookupItemIDs)(IOPCItemProperties * This, LPWSTR szItemID, DWORD dwCount, DWORD *pdwPropertyIDs, LPWSTR **ppszNewItemIDs, HRESULT **ppErrors);
    };
"""

SetLocalType(-1, IOPCItemPropertiesVtbl_str, 0)
Til2Idb(-1, "IOPCItemPropertiesVtbl")

IOPCItemDeadbandMgt_str = """
    struct IOPCItemDeadbandMgt
    {
        struct IOPCItemDeadbandMgtVtbl *lpVtbl;
    };
"""
SetLocalType(-1, IOPCItemDeadbandMgt_str, 0)
Til2Idb(-1, "IOPCItemDeadbandMgt")

IOPCItemDeadbandMgtVtbl_str = """
    struct IOPCItemDeadbandMgtVtbl
    {
        HRESULT (__stdcall *QueryInterface)(IOPCItemDeadbandMgt * This, IID * riid, void **ppvObject);
        ULONG (__stdcall *AddRef)(IOPCItemDeadbandMgt * This);
        ULONG (__stdcall *Release)(IOPCItemDeadbandMgt * This);
        HRESULT (__stdcall *SetItemDeadband)(IOPCItemDeadbandMgt * This, DWORD dwCount, OPCHANDLE *phServer, FLOAT *pPercentDeadband, HRESULT **ppErrors);
        HRESULT (__stdcall *GetItemDeadband)(IOPCItemDeadbandMgt * This, DWORD dwCount, OPCHANDLE *phServer, FLOAT **ppPercentDeadband, HRESULT **ppErrors);
        HRESULT (__stdcall *ClearItemDeadband)(IOPCItemDeadbandMgt * This, DWORD dwCount, OPCHANDLE *phServer, HRESULT **ppErrors);
    };
"""

SetLocalType(-1, IOPCItemDeadbandMgtVtbl_str, 0)
Til2Idb(-1, "IOPCItemDeadbandMgtVtbl")

IOPCItemSamplingMgt_str = """
    struct IOPCItemSamplingMgt
    {
        struct IOPCItemSamplingMgtVtbl *lpVtbl;
    };
"""
SetLocalType(-1, IOPCItemSamplingMgt_str, 0)
Til2Idb(-1, "IOPCItemSamplingMgt")

IOPCItemSamplingMgtVtbl_str = """
    struct IOPCItemSamplingMgtVtbl
    {
        HRESULT (__stdcall *QueryInterface)(IOPCItemSamplingMgt * This, IID * riid, void **ppvObject);
        ULONG (__stdcall *AddRef)(IOPCItemSamplingMgt * This);
        ULONG (__stdcall *Release)(IOPCItemSamplingMgt * This);
        HRESULT (__stdcall *SetItemSamplingRate)(IOPCItemSamplingMgt * This, DWORD dwCount, OPCHANDLE *phServer, DWORD *pdwRequestedSamplingRate, DWORD **ppdwRevisedSamplingRate, HRESULT **ppErrors);
        HRESULT (__stdcall *GetItemSamplingRate)(IOPCItemSamplingMgt * This, DWORD dwCount, OPCHANDLE *phServer, DWORD **ppdwSamplingRate, HRESULT **ppErrors);
        HRESULT (__stdcall *ClearItemSamplingRate)(IOPCItemSamplingMgt * This, DWORD dwCount, OPCHANDLE *phServer, HRESULT **ppErrors);
        HRESULT (__stdcall *SetItemBufferEnable)(IOPCItemSamplingMgt * This, DWORD dwCount, OPCHANDLE *phServer, BOOL *pbEnable, HRESULT **ppErrors);
        HRESULT (__stdcall *GetItemBufferEnable)(IOPCItemSamplingMgt * This, DWORD dwCount, OPCHANDLE *phServer, BOOL **ppbEnable, HRESULT **ppErrors);
    };
"""

SetLocalType(-1, IOPCItemSamplingMgtVtbl_str, 0)
Til2Idb(-1, "IOPCItemSamplingMgtVtbl")

IOPCBrowse_str = """
    struct IOPCBrowse
    {
        struct IOPCBrowseVtbl *lpVtbl;
    };
"""
SetLocalType(-1, IOPCBrowse_str, 0)
Til2Idb(-1, "IOPCBrowse")

IOPCBrowseVtbl_str = """
    struct IOPCBrowseVtbl
    {
        HRESULT (__stdcall *QueryInterface)(IOPCBrowse * This, IID * riid, void **ppvObject);
        ULONG (__stdcall *AddRef)(IOPCBrowse * This);
        ULONG (__stdcall *Release)(IOPCBrowse * This);
        HRESULT (__stdcall *GetProperties)(IOPCBrowse * This, DWORD dwItemCount, LPWSTR *pszItemIDs, BOOL bReturnPropertyValues, DWORD dwPropertyCount, DWORD *pdwPropertyIDs, OPCITEMPROPERTIES **ppItemProperties);
        HRESULT (__stdcall *Browse)(IOPCBrowse * This, LPWSTR szItemID, LPWSTR *pszContinuationPoint, DWORD dwMaxElementsReturned, OPCBROWSEFILTER dwBrowseFilter, LPWSTR szElementNameFilter, LPWSTR szVendorFilter, BOOL bReturnAllProperties, BOOL bReturnPropertyValues, DWORD dwPropertyCount, DWORD *pdwPropertyIDs, BOOL *pbMoreElements, DWORD *pdwCount, OPCBROWSEELEMENT **ppBrowseElements);
    };
"""

SetLocalType(-1, IOPCBrowseVtbl_str, 0)
Til2Idb(-1, "IOPCBrowseVtbl")

IOPCItemIO_str = """
    struct IOPCItemIO
    {
        struct IOPCItemIOVtbl *lpVtbl;
    };
"""
SetLocalType(-1, IOPCItemIO_str, 0)
Til2Idb(-1, "IOPCItemIO")

IOPCItemIOVtbl_str = """
    struct IOPCItemIOVtbl
    {
        HRESULT (__stdcall *QueryInterface)(IOPCItemIO * This, IID * riid, void **ppvObject);
        ULONG (__stdcall *AddRef)(IOPCItemIO * This);
        ULONG (__stdcall *Release)(IOPCItemIO * This);
        HRESULT (__stdcall *Read)(IOPCItemIO * This, DWORD dwCount, LPCWSTR *pszItemIDs, DWORD *pdwMaxAge, VARIANT **ppvValues, WORD **ppwQualities, FILETIME **ppftTimeStamps, HRESULT **ppErrors);
        HRESULT (__stdcall *WriteVQT)(IOPCItemIO * This, DWORD dwCount, LPCWSTR *pszItemIDs, OPCITEMVQT *pItemVQT, HRESULT **ppErrors);
    };
"""

SetLocalType(-1, IOPCItemIOVtbl_str, 0)
Til2Idb(-1, "IOPCItemIOVtbl")

IOPCSyncIO2_str = """
    struct IOPCSyncIO2
    {
        struct IOPCSyncIO2Vtbl *lpVtbl;
    };
"""
SetLocalType(-1, IOPCSyncIO2_str, 0)
Til2Idb(-1, "IOPCSyncIO2")

IOPCSyncIO2Vtbl_str = """
    struct IOPCSyncIO2Vtbl
    {
        HRESULT (__stdcall *QueryInterface)(IOPCSyncIO2 * This, IID * riid, void **ppvObject);
        ULONG (__stdcall *AddRef)(IOPCSyncIO2 * This);
        ULONG (__stdcall *Release)(IOPCSyncIO2 * This);
        HRESULT (__stdcall *Read)(IOPCSyncIO2 * This, OPCDATASOURCE dwSource, DWORD dwCount, OPCHANDLE *phServer, OPCITEMSTATE **ppItemValues, HRESULT **ppErrors);
        HRESULT (__stdcall *Write)(IOPCSyncIO2 * This, DWORD dwCount, OPCHANDLE *phServer, VARIANT *pItemValues, HRESULT **ppErrors);
        HRESULT (__stdcall *ReadMaxAge)(IOPCSyncIO2 * This, DWORD dwCount, OPCHANDLE *phServer, DWORD *pdwMaxAge, VARIANT **ppvValues, WORD **ppwQualities, FILETIME **ppftTimeStamps, HRESULT **ppErrors);
        HRESULT (__stdcall *WriteVQT)(IOPCSyncIO2 * This, DWORD dwCount, OPCHANDLE *phServer, OPCITEMVQT *pItemVQT, HRESULT **ppErrors);
    };
"""

SetLocalType(-1, IOPCSyncIO2Vtbl_str, 0)
Til2Idb(-1, "IOPCSyncIO2Vtbl")

IOPCAsyncIO3_str = """
    struct IOPCAsyncIO3
    {
        struct IOPCAsyncIO3Vtbl *lpVtbl;
    };
"""
SetLocalType(-1, IOPCAsyncIO3_str, 0)
Til2Idb(-1, "IOPCAsyncIO3")

IOPCAsyncIO3Vtbl_str = """
    struct IOPCAsyncIO3Vtbl
    {
        HRESULT (__stdcall *QueryInterface)(IOPCAsyncIO3 * This, IID * riid, void **ppvObject);
        ULONG (__stdcall *AddRef)(IOPCAsyncIO3 * This);
        ULONG (__stdcall *Release)(IOPCAsyncIO3 * This);
        HRESULT (__stdcall *Read)(IOPCAsyncIO3 * This, DWORD dwCount, OPCHANDLE *phServer, DWORD dwTransactionID, DWORD *pdwCancelID, HRESULT **ppErrors);
        HRESULT (__stdcall *Write)(IOPCAsyncIO3 * This, DWORD dwCount, OPCHANDLE *phServer, VARIANT *pItemValues, DWORD dwTransactionID, DWORD *pdwCancelID, HRESULT **ppErrors);
        HRESULT (__stdcall *Refresh2)(IOPCAsyncIO3 * This, OPCDATASOURCE dwSource, DWORD dwTransactionID, DWORD *pdwCancelID);
        HRESULT (__stdcall *Cancel2)(IOPCAsyncIO3 * This, DWORD dwCancelID);
        HRESULT (__stdcall *SetEnable)(IOPCAsyncIO3 * This, BOOL bEnable);
        HRESULT (__stdcall *GetEnable)(IOPCAsyncIO3 * This, BOOL *pbEnable);
        HRESULT (__stdcall *ReadMaxAge)(IOPCAsyncIO3 * This, DWORD dwCount, OPCHANDLE *phServer, DWORD *pdwMaxAge, DWORD dwTransactionID, DWORD *pdwCancelID, HRESULT **ppErrors);
        HRESULT (__stdcall *WriteVQT)(IOPCAsyncIO3 * This, DWORD dwCount, OPCHANDLE *phServer, OPCITEMVQT *pItemVQT, DWORD dwTransactionID, DWORD *pdwCancelID, HRESULT **ppErrors);
        HRESULT (__stdcall *RefreshMaxAge)(IOPCAsyncIO3 * This, DWORD dwMaxAge, DWORD dwTransactionID, DWORD *pdwCancelID);
    };
"""

SetLocalType(-1, IOPCAsyncIO3Vtbl_str, 0)
Til2Idb(-1, "IOPCAsyncIO3Vtbl")

IOPCGroupStateMgt2_str = """
    struct IOPCGroupStateMgt2
    {
        struct IOPCGroupStateMgt2Vtbl *lpVtbl;
    };
"""
SetLocalType(-1, IOPCGroupStateMgt2_str, 0)
Til2Idb(-1, "IOPCGroupStateMgt2")

IOPCGroupStateMgt2Vtbl_str = """
    struct IOPCGroupStateMgt2Vtbl
    {
        HRESULT (__stdcall *QueryInterface)(IOPCGroupStateMgt2 * This, IID * riid, void **ppvObject);
        ULONG (__stdcall *AddRef)(IOPCGroupStateMgt2 * This);
        ULONG (__stdcall *Release)(IOPCGroupStateMgt2 * This);
        HRESULT (__stdcall *GetState)(IOPCGroupStateMgt2 * This, DWORD *pUpdateRate, BOOL *pActive, LPWSTR *ppName, LONG *pTimeBias, FLOAT *pPercentDeadband, DWORD *pLCID, OPCHANDLE *phClientGroup, OPCHANDLE *phServerGroup);
        HRESULT (__stdcall *SetState)(IOPCGroupStateMgt2 * This, DWORD *pRequestedUpdateRate, DWORD *pRevisedUpdateRate, BOOL *pActive, LONG *pTimeBias, FLOAT *pPercentDeadband, DWORD *pLCID, OPCHANDLE *phClientGroup);
        HRESULT (__stdcall *SetName)(IOPCGroupStateMgt2 * This, LPCWSTR szName);
        HRESULT (__stdcall *CloneGroup)(IOPCGroupStateMgt2 * This, LPCWSTR szName, IID * riid, LPUNKNOWN *ppUnk);
        HRESULT (__stdcall *SetKeepAlive)(IOPCGroupStateMgt2 * This, DWORD dwKeepAliveTime, DWORD *pdwRevisedKeepAliveTime);
        HRESULT (__stdcall *GetKeepAlive)(IOPCGroupStateMgt2 * This, DWORD *pdwKeepAliveTime);
    };
"""

SetLocalType(-1, IOPCGroupStateMgt2Vtbl_str, 0)
Til2Idb(-1, "IOPCGroupStateMgt2Vtbl")

enum_id = AddEnum(-1, 'OPCDA_Constants', 0)
AddConstEx(enum_id, 'OPC_READABLE', 1, -1)
AddConstEx(enum_id, 'OPC_WRITEABLE', 2, -1)
AddConstEx(enum_id, 'OPC_BROWSE_HASCHILDREN', 1, -1)
AddConstEx(enum_id, 'OPC_BROWSE_ISITEM', 2, -1)

enum_id = AddEnum(-1, 'OPCDA_Qualities', 0)
AddConstEx(enum_id, 'OPC_QUALITY_MASK', 0xc0, -1)
AddConstEx(enum_id, 'OPC_STATUS_MASK', 0xfc, -1)
AddConstEx(enum_id, 'OPC_LIMIT_MASK', 0x3, -1)
AddConstEx(enum_id, 'OPC_QUALITY_BAD', 0, -1)
AddConstEx(enum_id, 'OPC_QUALITY_UNCERTAIN', 0x40, -1)
AddConstEx(enum_id, 'OPC_QUALITY_GOOD', 0xc0, -1)
AddConstEx(enum_id, 'OPC_QUALITY_CONFIG_ERROR', 0x4, -1)
AddConstEx(enum_id, 'OPC_QUALITY_NOT_CONNECTED', 0x8, -1)
AddConstEx(enum_id, 'OPC_QUALITY_DEVICE_FAILURE', 0xc, -1)
AddConstEx(enum_id, 'OPC_QUALITY_SENSOR_FAILURE', 0x10, -1)
AddConstEx(enum_id, 'OPC_QUALITY_LAST_KNOWN', 0x14, -1)
AddConstEx(enum_id, 'OPC_QUALITY_COMM_FAILURE', 0x18, -1)
AddConstEx(enum_id, 'OPC_QUALITY_OUT_OF_SERVICE', 0x1c, -1)
AddConstEx(enum_id, 'OPC_QUALITY_WAITING_FOR_INITIAL_DATA', 0x20, -1)
AddConstEx(enum_id, 'OPC_QUALITY_LAST_USABLE', 0x44, -1)
AddConstEx(enum_id, 'OPC_QUALITY_SENSOR_CAL', 0x50, -1)
AddConstEx(enum_id, 'OPC_QUALITY_EGU_EXCEEDED', 0x54, -1)
AddConstEx(enum_id, 'OPC_QUALITY_SUB_NORMAL', 0x58, -1)
AddConstEx(enum_id, 'OPC_QUALITY_LOCAL_OVERRIDE', 0xd8, -1)
AddConstEx(enum_id, 'OPC_LIMIT_OK', 0, -1)
AddConstEx(enum_id, 'OPC_LIMIT_LOW', 0x1, -1)
AddConstEx(enum_id, 'OPC_LIMIT_HIGH', 0x2, -1)
AddConstEx(enum_id, 'OPC_LIMIT_CONST', 0x3, -1)

enum_id = AddEnum(-1, 'OPCDA_Properties', 0)
AddConstEx(enum_id, 'OPC_PROPERTY_DATATYPE', 1, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_VALUE', 2, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_QUALITY', 3, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_TIMESTAMP', 4, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_ACCESS_RIGHTS', 5, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_SCAN_RATE', 6, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_EU_TYPE', 7, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_EU_INFO', 8, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_EU_UNITS', 100, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_DESCRIPTION', 101, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_HIGH_EU', 102, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_LOW_EU', 103, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_HIGH_IR', 104, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_LOW_IR', 105, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_CLOSE_LABEL', 106, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_OPEN_LABEL', 107, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_TIMEZONE', 108, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_CONDITION_STATUS', 300, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_ALARM_QUICK_HELP', 301, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_ALARM_AREA_LIST', 302, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_PRIMARY_ALARM_AREA', 303, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_CONDITION_LOGIC', 304, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_LIMIT_EXCEEDED', 305, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_DEADBAND', 306, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_HIHI_LIMIT', 307, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_HI_LIMIT', 308, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_LO_LIMIT', 309, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_LOLO_LIMIT', 310, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_CHANGE_RATE_LIMIT', 311, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_DEVIATION_LIMIT', 312, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_SOUND_FILE', 313, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_TYPE_SYSTEM_ID', 600, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_DICTIONARY_ID', 601, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_TYPE_ID', 602, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_DICTIONARY', 603, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_TYPE_DESCRIPTION', 604, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_CONSISTENCY_WINDOW', 605, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_WRITE_BEHAVIOR', 606, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_UNCONVERTED_ITEM_ID', 607, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_UNFILTERED_ITEM_ID', 608, -1)
AddConstEx(enum_id, 'OPC_PROPERTY_DATA_FILTER_VALUE', 609, -1)
