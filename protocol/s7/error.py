"""
Snap7 library error codes.

we define all error codes here, but we don't use them (yet/anymore).
The error code formatting of the snap7 library as already quite good,
so we are using that now. But maybe we will use this in the future again.
"""

s7_client_errors = {
    0x00100000: 'errNegotiatingPDU',
    0x00200000: 'errCliInvalidParams',
    0x00300000: 'errCliJobPending',
    0x00400000: 'errCliTooManyItems',
    0x00500000: 'errCliInvalidWordLen',
    0x00600000: 'errCliPartialDataWritten',
    0x00700000: 'errCliSizeOverPDU',
    0x00800000: 'errCliInvalidPlcAnswer',
    0x00900000: 'errCliAddressOutOfRange',
    0x00A00000: 'errCliInvalidTransportSize',
    0x00B00000: 'errCliWriteDataSizeMismatch',
    0x00C00000: 'errCliItemNotAvailable',
    0x00D00000: 'errCliInvalidValue',
    0x00E00000: 'errCliCannotStartPLC',
    0x00F00000: 'errCliAlreadyRun',
    0x01000000: 'errCliCannotStopPLC',
    0x01100000: 'errCliCannotCopyRamToRom',
    0x01200000: 'errCliCannotCompress',
    0x01300000: 'errCliAlreadyStop',
    0x01400000: 'errCliFunNotAvailable',
    0x01500000: 'errCliUploadSequenceFailed',
    0x01600000: 'errCliInvalidDataSizeRecvd',
    0x01700000: 'errCliInvalidBlockType',
    0x01800000: 'errCliInvalidBlockNumber',
    0x01900000: 'errCliInvalidBlockSize',
    0x01A00000: 'errCliDownloadSequenceFailed',
    0x01B00000: 'errCliInsertRefused',
    0x01C00000: 'errCliDeleteRefused',
    0x01D00000: 'errCliNeedPassword',
    0x01E00000: 'errCliInvalidPassword',
    0x01F00000: 'errCliNoPasswordToSetOrClear',
    0x02000000: 'errCliJobTimeout',
    0x02100000: 'errCliPartialDataRead',
    0x02200000: 'errCliBufferTooSmall',
    0x02300000: 'errCliFunctionRefused',
    0x02400000: 'errCliDestroying',
    0x02500000: 'errCliInvalidParamNumber',
    0x02600000: 'errCliCannotChangeParam',
}

isotcp_errors = {
    0x00010000: 'errIsoConnect',
    0x00020000: 'errIsoDisconnect',
    0x00030000: 'errIsoInvalidPDU',
    0x00040000: 'errIsoInvalidDataSize',
    0x00050000: 'errIsoNullPointer',
    0x00060000: 'errIsoShortPacket',
    0x00070000: 'errIsoTooManyFragments',
    0x00080000: 'errIsoPduOverflow',
    0x00090000: 'errIsoSendPacket',
    0x000A0000: 'errIsoRecvPacket',
    0x000B0000: 'errIsoInvalidParams',
    0x000C0000: 'errIsoResvd_1',
    0x000D0000: 'errIsoResvd_2',
    0x000E0000: 'errIsoResvd_3',
    0x000F0000: 'errIsoResvd_4',
}

tcp_errors = {
    0x00000001: 'evcServerStarted',
    0x00000002: 'evcServerStopped',
    0x00000004: 'evcListenerCannotStart',
    0x00000008: 'evcClientAdded',
    0x00000010: 'evcClientRejected',
    0x00000020: 'evcClientNoRoom',
    0x00000040: 'evcClientException',
    0x00000080: 'evcClientDisconnected',
    0x00000100: 'evcClientTerminated',
    0x00000200: 'evcClientsDropped',
    0x00000400: 'evcReserved_00000400',
    0x00000800: 'evcReserved_00000800',
    0x00001000: 'evcReserved_00001000',
    0x00002000: 'evcReserved_00002000',
    0x00004000: 'evcReserved_00004000',
    0x00008000: 'evcReserved_00008000',
}

s7_server_errors = {
    0x00100000: 'errSrvCannotStart',
    0x00200000: 'errSrvDBNullPointer',
    0x00300000: 'errSrvAreaAlreadyExists',
    0x00400000: 'errSrvUnknownArea',
    0x00500000: 'verrSrvInvalidParams',
    0x00600000: 'errSrvTooManyDB',
    0x00700000: 'errSrvInvalidParamNumber',
    0x00800000: 'errSrvCannotChangeParam',
}


client_errors = s7_client_errors.copy()
client_errors.update(isotcp_errors)
client_errors.update(tcp_errors)

server_errors = s7_server_errors.copy()
server_errors.update(isotcp_errors)
server_errors.update(tcp_errors)


