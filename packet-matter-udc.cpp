/*
 *  Copyright (c) 2023 Project CHIP Authors.
 *
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdint.h>
#include <stdio.h>

#include <glib.h>

#include "config.h"

#include <epan/packet.h>

#include <Matter/Core/MatterTLV.h>
#include <Matter/Protocols/MatterProfiles.h>
#include <Matter/Support/CodeUtils.h>

#include "packet-matter.h"
#include "TLVDissector.h"

using namespace matter::TLV;
using namespace matter::Profiles;

static int proto_udc = -1;
static int ett_udc   = -1;
static int ett_udc_target_app = -1;
static int ett_udc_target_app_list = -1;

static int hf_UDC_InstanceName = -1;
static int hf_UDC_IgnoreByte   = -1;
static int hf_UDC_TLVData      = -1;
static int hf_UDC_RawPayload   = -1;
static int hf_UDC_VendorId = -1;
static int hf_UDC_ProductId = -1;
static int hf_UDC_DeviceName = -1;
static int hf_UDC_DeviceType = -1;
static int hf_UDC_PairingInst = -1;
static int hf_UDC_PairingHint = -1;
static int hf_UDC_RotatingId = -1;
static int hf_UDC_CdPort = -1;
static int hf_UDC_TargetAppList = -1;
static int hf_UDC_TargetApp = -1;
static int hf_UDC_AppVendorId = -1;
static int hf_UDC_AppProductId = -1;
static int hf_UDC_NoPasscode = -1;
static int hf_UDC_CdUponPasscodeDialog = -1;
static int hf_UDC_CommissionerPasscode = -1;
static int hf_UDC_CommissionerPasscodeReady = -1;
static int hf_UDC_CancelPasscode = -1;
static int hf_UDC_PasscodeLength = -1;
static int hf_UDC_UnknownTag = -1;

namespace {
constexpr uint8_t kUDCMsgType_IdentificationDeclaration = 0x00;

enum UdcIdTag : uint8_t
{
    kVendorIdTag = 1,
    kProductIdTag = 2,
    kDeviceNameTag = 3,
    kDeviceTypeTag = 4,
    kPairingInstTag = 5,
    kPairingHintTag = 6,
    kRotatingIdTag = 7,
    kCdPortTag = 8,
    kTargetAppListTag = 9,
    kTargetAppTag = 10,
    kAppVendorIdTag = 11,
    kAppProductIdTag = 12,
    kNoPasscodeTag = 13,
    kCdUponPasscodeDialogTag = 14,
    kCommissionerPasscodeTag = 15,
    kCommissionerPasscodeReadyTag = 16,
    kCancelPasscodeTag = 17,
    kPasscodeLengthTag = 18,
};
}

static MATTER_ERROR AddUDCTargetApp(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb)
{
    MATTER_ERROR err;
    proto_tree * targetAppTree;

    VerifyOrExit(tlvDissector.GetType() == kTLVType_Structure, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
    err = tlvDissector.AddSubTreeItem(tree, hf_UDC_TargetApp, ett_udc_target_app, tvb, targetAppTree);
    SuccessOrExit(err);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true)
    {
        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV)
        {
            break;
        }
        SuccessOrExit(err);

        uint64_t tag = tlvDissector.GetTag();
        VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

        switch (TagNumFromTag(tag))
        {
        case kAppVendorIdTag:
            err = tlvDissector.AddTypedItem(targetAppTree, hf_UDC_AppVendorId, tvb);
            SuccessOrExit(err);
            break;
        case kAppProductIdTag:
            err = tlvDissector.AddTypedItem(targetAppTree, hf_UDC_AppProductId, tvb);
            SuccessOrExit(err);
            break;
        default:
            err = tlvDissector.AddGenericTLVItem(targetAppTree, hf_UDC_UnknownTag, tvb, false);
            SuccessOrExit(err);
            break;
        }
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

static int DissectUDCIdentificationDeclaration(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree,
                                               const MatterMessageInfo & msgInfo)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    proto_item_append_text(proto_tree_get_parent(tree), ": IdentificationDeclaration");

    int payloadLen = msgInfo.payloadLen;
    if (payloadLen <= 0)
    {
        return 0;
    }

    int newlinePos = tvb_find_uint8(tvb, 0, payloadLen, '\n');
    if (newlinePos >= 0)
    {
        if (newlinePos > 0)
        {
            proto_tree_add_item(tree, hf_UDC_InstanceName, tvb, 0, newlinePos, ENC_ASCII | ENC_NA);
        }
        else
        {
            proto_tree_add_string(tree, hf_UDC_InstanceName, tvb, 0, 0, "");
        }

        int cursor = newlinePos + 1;
        if (cursor < payloadLen)
        {
            proto_tree_add_item(tree, hf_UDC_IgnoreByte, tvb, cursor, 1, ENC_LITTLE_ENDIAN);
            cursor += 1;
        }

        if (cursor < payloadLen)
        {
            proto_tree_add_item(tree, hf_UDC_TLVData, tvb, cursor, payloadLen - cursor, ENC_NA);
            const uint8_t * tlvData = (const uint8_t *) tvb_memdup(pinfo->pool, tvb, cursor, payloadLen - cursor);
            TLVDissector tlvDissector;
            tlvDissector.Init(tlvData, payloadLen - cursor, cursor);
            tlvDissector.ImplicitProfileId = kMatterProfile_UDC;

            err = tlvDissector.Next(kTLVType_Structure, AnonymousTag);
            if (err == MATTER_NO_ERROR)
            {
                err = tlvDissector.EnterContainer();
            }
            if (err == MATTER_NO_ERROR)
            {
                while (true)
                {
                    err = tlvDissector.Next();
                    if (err == MATTER_END_OF_TLV)
                    {
                        err = MATTER_NO_ERROR;
                        break;
                    }
                    SuccessOrExit(err);

                    uint64_t tag = tlvDissector.GetTag();
                    VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

                    switch (TagNumFromTag(tag))
                    {
                    case kVendorIdTag:
                        err = tlvDissector.AddTypedItem(tree, hf_UDC_VendorId, tvb);
                        break;
                    case kProductIdTag:
                        err = tlvDissector.AddTypedItem(tree, hf_UDC_ProductId, tvb);
                        break;
                    case kDeviceNameTag:
                        err = tlvDissector.AddTypedItem(tree, hf_UDC_DeviceName, tvb);
                        break;
                    case kDeviceTypeTag:
                        err = tlvDissector.AddTypedItem(tree, hf_UDC_DeviceType, tvb);
                        break;
                    case kPairingInstTag:
                        err = tlvDissector.AddTypedItem(tree, hf_UDC_PairingInst, tvb);
                        break;
                    case kPairingHintTag:
                        err = tlvDissector.AddTypedItem(tree, hf_UDC_PairingHint, tvb);
                        break;
                    case kRotatingIdTag:
                        err = tlvDissector.AddTypedItem(tree, hf_UDC_RotatingId, tvb);
                        break;
                    case kCdPortTag:
                        err = tlvDissector.AddTypedItem(tree, hf_UDC_CdPort, tvb);
                        break;
                    case kTargetAppListTag:
                        if (tlvDissector.GetType() == kTLVType_Array)
                        {
                            err = tlvDissector.AddListItem(tree, hf_UDC_TargetAppList, ett_udc_target_app_list, tvb, AddUDCTargetApp);
                        }
                        else
                        {
                            err = tlvDissector.AddGenericTLVItem(tree, hf_UDC_UnknownTag, tvb, false);
                        }
                        break;
                    case kNoPasscodeTag:
                        err = tlvDissector.AddTypedItem(tree, hf_UDC_NoPasscode, tvb);
                        break;
                    case kCdUponPasscodeDialogTag:
                        err = tlvDissector.AddTypedItem(tree, hf_UDC_CdUponPasscodeDialog, tvb);
                        break;
                    case kCommissionerPasscodeTag:
                        err = tlvDissector.AddTypedItem(tree, hf_UDC_CommissionerPasscode, tvb);
                        break;
                    case kCommissionerPasscodeReadyTag:
                        err = tlvDissector.AddTypedItem(tree, hf_UDC_CommissionerPasscodeReady, tvb);
                        break;
                    case kCancelPasscodeTag:
                        err = tlvDissector.AddTypedItem(tree, hf_UDC_CancelPasscode, tvb);
                        break;
                    case kPasscodeLengthTag:
                        err = tlvDissector.AddTypedItem(tree, hf_UDC_PasscodeLength, tvb);
                        break;
                    default:
                        err = tlvDissector.AddGenericTLVItem(tree, hf_UDC_UnknownTag, tvb, false);
                        break;
                    }
                    SuccessOrExit(err);
                }
            }
            if (err == MATTER_NO_ERROR)
            {
                err = tlvDissector.ExitContainer();
            }
        }
    }
    else
    {
        proto_tree_add_item(tree, hf_UDC_RawPayload, tvb, 0, payloadLen, ENC_NA);
    }

    col_prepend_fstr(pinfo->cinfo, COL_INFO, "UDC:IdentificationDeclaration ");

exit:
    return payloadLen;
}

static int DissectUDC(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree _U_, void * data _U_)
{
    const MatterMessageInfo & msgInfo = *(const MatterMessageInfo *) data;

    AddMessageTypeToInfoColumn(pinfo, msgInfo);

    proto_item * top   = proto_tree_add_item(tree, proto_udc, tvb, 0, -1, ENC_NA);
    proto_tree * udcTree = proto_item_add_subtree(top, ett_udc);

    switch (msgInfo.msgType)
    {
    case kUDCMsgType_IdentificationDeclaration:
        return DissectUDCIdentificationDeclaration(tvb, pinfo, udcTree, msgInfo);
    default:
        if (msgInfo.payloadLen > 0)
        {
            proto_tree_add_item(udcTree, hf_UDC_RawPayload, tvb, 0, msgInfo.payloadLen, ENC_NA);
        }
        return msgInfo.payloadLen;
    }
}

void proto_register_matter_udc(void)
{
    static hf_register_info hf[] = {
        { &hf_UDC_InstanceName,
          { "Instance Name", "matter.udc.instance_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_UDC_IgnoreByte,
          { "Ignore Byte", "matter.udc.ignore", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_UDC_TLVData,
          { "UDC TLV Data", "matter.udc.tlv_data", FT_BYTES, SEP_SPACE, NULL, 0x0, NULL, HFILL } },
        { &hf_UDC_RawPayload,
          { "UDC Payload", "matter.udc.payload", FT_BYTES, SEP_SPACE, NULL, 0x0, NULL, HFILL } },
        { &hf_UDC_VendorId,
          { "Vendor ID", "matter.udc.vendor_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_UDC_ProductId,
          { "Product ID", "matter.udc.product_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_UDC_DeviceName,
          { "Device Name", "matter.udc.device_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_UDC_DeviceType,
          { "Device Type", "matter.udc.device_type", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_UDC_PairingInst,
          { "Pairing Instruction", "matter.udc.pairing_instruction", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_UDC_PairingHint,
          { "Pairing Hint", "matter.udc.pairing_hint", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_UDC_RotatingId,
          { "Rotating ID", "matter.udc.rotating_id", FT_BYTES, SEP_SPACE, NULL, 0x0, NULL, HFILL } },
        { &hf_UDC_CdPort,
          { "CD Port", "matter.udc.cd_port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_UDC_TargetAppList,
          { "Target App List", "matter.udc.target_app_list", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_UDC_TargetApp,
          { "Target App", "matter.udc.target_app", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_UDC_AppVendorId,
          { "App Vendor ID", "matter.udc.target_app.vendor_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_UDC_AppProductId,
          { "App Product ID", "matter.udc.target_app.product_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_UDC_NoPasscode,
          { "No Passcode", "matter.udc.no_passcode", FT_BOOLEAN, 8, NULL, 0x0, NULL, HFILL } },
        { &hf_UDC_CdUponPasscodeDialog,
          { "CD Upon Passcode Dialog", "matter.udc.cd_upon_passcode_dialog", FT_BOOLEAN, 8, NULL, 0x0, NULL, HFILL } },
        { &hf_UDC_CommissionerPasscode,
          { "Commissioner Passcode", "matter.udc.commissioner_passcode", FT_BOOLEAN, 8, NULL, 0x0, NULL, HFILL } },
        { &hf_UDC_CommissionerPasscodeReady,
          { "Commissioner Passcode Ready", "matter.udc.commissioner_passcode_ready", FT_BOOLEAN, 8, NULL, 0x0, NULL, HFILL } },
        { &hf_UDC_CancelPasscode,
          { "Cancel Passcode", "matter.udc.cancel_passcode", FT_BOOLEAN, 8, NULL, 0x0, NULL, HFILL } },
        { &hf_UDC_PasscodeLength,
          { "Passcode Length", "matter.udc.passcode_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_UDC_UnknownTag,
          { "Unknown Tag", "matter.udc.unknown", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    };

    static gint * ett[] = {
        &ett_udc,
        &ett_udc_target_app,
        &ett_udc_target_app_list,
    };

    proto_udc = proto_register_protocol("Matter User Directed Commissioning Protocol", "UDC", "matter-udc");
    proto_register_field_array(proto_udc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_matter_udc(void)
{
    static dissector_handle_t matter_udc_handle;

    matter_udc_handle = create_dissector_handle(DissectUDC, proto_udc);
    dissector_add_uint("matter.profile_id", kMatterProfile_UDC, matter_udc_handle);
}
