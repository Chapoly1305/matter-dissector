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
#include <inttypes.h>
#include <stdio.h>
#include <string>

#include <glib.h>

#include "config.h"

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/conversation_filter.h>

#include <Matter/Core/MatterCore.h>
#include <Matter/Core/MatterTLV.h>
#include <Matter/Protocols/MatterProfiles.h>
#include <Matter/Protocols/security/MatterSecurity.h>
#include <Matter/Protocols/interaction-model/MessageDef.h>
#include <Matter/Support/CodeUtils.h>

#include "packet-matter.h"
#include "TLVDissector.h"
#include "MatterMessageTracker.h"

using namespace matter;
using namespace matter::TLV;
using namespace matter::Profiles;
using namespace matter::Profiles::Security;
using namespace matter::Profiles::InteractionModel;

static int proto_im = -1;

static int ett_im = -1;
static int ett_im_message_container = -1;
static int ett_SubscribeRequest_LastObservedEventList = -1;
static int ett_SubscribeRequest_PathList = -1;
static int ett_SubscribeRequest_VersionList = -1;
static int ett_SubscribeResponse_LastVendedEventList = -1;
static int ett_CommandRequest_CommandList = -1;
static int ett_CommandResponse_InvokeResponseList = -1;

static int ett_CommandElem = -1;
static int ett_DataElem = -1;
static int ett_StatusIB = -1;

static int hf_IM_SubscriptionId = -1;

static int hf_StatusResponse_Status = -1;

static int hf_ReadRequest_AttributeRequests = -1;
static int hf_ReadRequest_EventRequests = -1;
static int hf_ReadRequest_EventFilters  = -1;
static int hf_ReadRequest_IsFabricFiltered = -1;
static int hf_ReadRequest_DataVersionFilters = -1;

static int hf_ReportData_SubscriptionID = -1;
static int hf_ReportData_AttributeReports = -1;
static int hf_ReportData_EventReports = -1;
static int hf_ReportData_MoreChunkedMessages = -1;
static int hf_ReportData_SuppressResponse = -1;

static int hf_WriteResponse_WriteResponses = -1;

static int hf_WriteRequest_SuppressResponse = -1;
static int hf_WriteRequest_TimedRequest = -1;
static int hf_WriteRequest_WriteRequests = -1;
static int hf_WriteRequest_MoreChunkedMessages = -1;

static int hf_SubscribeRequest_KeepSubscriptions = -1;
static int hf_SubscribeRequest_MinIntervalFloor  = -1;
static int hf_SubscribeRequest_MaxIntervalCeiling = -1;
static int hf_SubscribeRequest_AttributeRequests = -1;
static int hf_SubscribeRequest_EventRequests = -1;
static int hf_SubscribeRequest_EventFilters = -1;
static int hf_SubscribeRequest_IsFabricFiltered = -1;
static int hf_SubscribeRequest_DataVersionFilters = -1;

static int hf_SubscribeResponse_SubscriptionID = -1;
static int hf_SubscribeResponse_MaxInterval = -1;

static int hf_CommandRequest_SuppressResponse = -1;
static int hf_CommandRequest_TimedRequest = -1;
static int hf_CommandRequest_CommandList = -1;
static int hf_CommandRequest_Path = -1;
static int hf_CommandRequest_CommandType = -1;
static int hf_CommandRequest_ExpiryTime = -1;
static int hf_CommandRequest_RequiredVersion = -1;
static int hf_CommandRequest_Argument = -1;

static int hf_CommandResponse_SuppressResponse = -1;
static int hf_CommandResponse_InvokeResponses = -1;

static int hf_CommandResponse_InvokeResponsesDetail = -1;
static int hf_CommandResponse_Version = -1;
static int hf_CommandResponse_Result = -1;
static int hf_CommandStatusIB = -1;
static int hf_CommandDataIB = -1;
static int hf_StatusIB = -1;
static int hf_CommandStatus_Status = -1;
static int hf_CommandStatus_ClusterStatus = -1;
static int hf_CommandStatus_Ref = -1;

static int hf_ImCommon_Version = -1;
static int hf_ImCommon_Unknown = -1;
static int hf_TimedRequest_TimeoutMs = -1;

static int hf_DataElem_PropertyPath = -1;
static int hf_DataElem_PropertyData = -1;

namespace
{
struct ClusterNameEntry
{
    uint32_t clusterId;
    const char *name;
};

struct ScopedNameEntry
{
    uint32_t clusterId;
    uint32_t id;
    const char *name;
};

#include "im_name_tables.inc"

const char * GetClusterNameById(uint32_t clusterId)
{
    for (const auto & entry : kClusterNameTable) {
        if (entry.clusterId == clusterId) {
            return entry.name;
        }
    }
    return nullptr;
}

const char * FindScopedName(const ScopedNameEntry *table, size_t tableSize, uint32_t clusterId, uint32_t id)
{
    for (size_t i = 0; i < tableSize; i++) {
        if (table[i].clusterId == clusterId && table[i].id == id) {
            return table[i].name;
        }
    }
    return nullptr;
}

const char * GetCommandNameById(uint32_t clusterId, uint32_t commandId)
{
    return FindScopedName(kCommandNameTable, array_length(kCommandNameTable), clusterId, commandId);
}

const char * GetAttributeNameById(uint32_t clusterId, uint32_t attributeId)
{
    return FindScopedName(kAttributeNameTable, array_length(kAttributeNameTable), clusterId, attributeId);
}

const char * GetEventNameById(uint32_t clusterId, uint32_t eventId)
{
    return FindScopedName(kEventNameTable, array_length(kEventNameTable), clusterId, eventId);
}

enum class PathKind
{
    Command,
    Attribute,
    Event,
};

static MATTER_ERROR AddNamedPathItem(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb, PathKind kind)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    bool endpointPresent = false;
    bool clusterPresent = false;
    bool itemPresent = false;
    uint32_t endpointId = 0;
    uint32_t clusterId = 0;
    uint32_t itemId = 0;
    const char *itemLabel = "Field";

    VerifyOrExit(tlvDissector.GetType() == kTLVType_Path || tlvDissector.GetType() == kTLVType_Structure,
                 err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true)
    {
        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV)
        {
            err = MATTER_NO_ERROR;
            break;
        }
        SuccessOrExit(err);

        const uint64_t tag = tlvDissector.GetTag();
        const TLVType type = tlvDissector.GetType();
        if (!IsContextTag(tag) || type != kTLVType_UnsignedInteger)
        {
            continue;
        }

        const uint32_t tagNum = TagNumFromTag(tag);
        uint64_t value = 0;
        err = tlvDissector.Get(value);
        SuccessOrExit(err);

        if (!endpointPresent && (tagNum == 0 || tagNum == 1))
        {
            endpointId = static_cast<uint32_t>(value);
            endpointPresent = true;
            continue;
        }

        if (!clusterPresent && (tagNum == 1 || tagNum == 2))
        {
            clusterId = static_cast<uint32_t>(value);
            clusterPresent = true;
            continue;
        }

        if (!itemPresent && (tagNum == 2 || tagNum == 3))
        {
            itemId = static_cast<uint32_t>(value);
            itemPresent = true;
            continue;
        }
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

    switch (kind)
    {
    case PathKind::Command:
        itemLabel = "Command";
        break;
    case PathKind::Attribute:
        itemLabel = "Attribute";
        break;
    case PathKind::Event:
        itemLabel = "Event";
        break;
    }

    {
        std::string out;
        if (endpointPresent)
        {
            char buf[48];
            snprintf(buf, sizeof(buf), "Endpoint=0x%X", endpointId);
            out += buf;
        }

        if (clusterPresent)
        {
            const char *clusterName = GetClusterNameById(clusterId);
            char buf[96];
            snprintf(buf, sizeof(buf), "%sCluster=0x%X%s%s",
                     out.empty() ? "" : ", ",
                     clusterId,
                     (clusterName != nullptr) ? " (" : "",
                     (clusterName != nullptr) ? clusterName : "");
            out += buf;
            if (clusterName != nullptr)
            {
                out += ")";
            }
        }

        if (itemPresent)
        {
            const char *itemName = nullptr;
            if (kind == PathKind::Command)
            {
                itemName = GetCommandNameById(clusterId, itemId);
            }
            else if (kind == PathKind::Attribute)
            {
                itemName = GetAttributeNameById(clusterId, itemId);
            }
            else
            {
                itemName = GetEventNameById(clusterId, itemId);
            }

            char buf[128];
            snprintf(buf, sizeof(buf), "%s%s=0x%X%s%s",
                     out.empty() ? "" : ", ",
                     itemLabel,
                     itemId,
                     (itemName != nullptr) ? " (" : "",
                     (itemName != nullptr) ? itemName : "");
            out += buf;
            if (itemName != nullptr)
            {
                out += ")";
            }
        }

        if (out.empty())
        {
            out = "Unknown Path";
        }
        err = tlvDissector.AddStringItemF(tree, hf_DataElem_PropertyPath, tvb, "%s", out.c_str());
        SuccessOrExit(err);
    }

exit:
    return err;
}

static MATTER_ERROR AddAttributePathItem(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb)
{
    return AddNamedPathItem(tlvDissector, tree, tvb, PathKind::Attribute);
}

static MATTER_ERROR AddEventPathItem(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb)
{
    return AddNamedPathItem(tlvDissector, tree, tvb, PathKind::Event);
}

static MATTER_ERROR AddNamedStructItem(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb, PathKind kind)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    proto_tree * itemTree = nullptr;

    VerifyOrExit(tlvDissector.GetType() == kTLVType_Structure, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
    err = tlvDissector.AddSubTreeItem(tree, hf_DataElem_PropertyData, ett_DataElem, tvb, itemTree);
    SuccessOrExit(err);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {
        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV) {
            err = MATTER_NO_ERROR;
            break;
        }
        SuccessOrExit(err);

        const TLVType type = tlvDissector.GetType();
        if (type == kTLVType_Path || type == kTLVType_Structure) {
            MATTER_ERROR pathErr = AddNamedPathItem(tlvDissector, itemTree, tvb, kind);
            if (pathErr == MATTER_NO_ERROR) {
                continue;
            }
        }

        err = tlvDissector.AddGenericTLVItem(itemTree, hf_DataElem_PropertyData, tvb, false);
        SuccessOrExit(err);
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

static MATTER_ERROR AddAttributeDataIBItem(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb)
{
    return AddNamedStructItem(tlvDissector, tree, tvb, PathKind::Attribute);
}

static MATTER_ERROR AddEventReportIBItem(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb)
{
    return AddNamedStructItem(tlvDissector, tree, tvb, PathKind::Event);
}
} // namespace

void AssociateWithIMSubscription(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, MatterMessageRecord *msgRec)
{
    if (msgRec->imSubscription == 0) {
        for (MatterMessageRecord *p = msgRec; p != NULL; p = p->prevByExchange) {
            if (p->imSubscription != 0) {
                msgRec->imSubscription = p->imSubscription;
                break;
            }
        }
    }

    if (msgRec->imSubscription == 0) {
        for (MatterMessageRecord *p = msgRec->nextByExchange; p != NULL; p = p->nextByExchange) {
            if (p->imSubscription != 0) {
                msgRec->imSubscription = p->imSubscription;
                break;
            }
        }
    }

//    if (msgRec->imSubscription != 0) {
        proto_item *item = proto_tree_add_uint64(tree, hf_IM_SubscriptionId, tvb, 0, 0, msgRec->imSubscription);
        PROTO_ITEM_SET_HIDDEN(item);
//    }
}


static MATTER_ERROR
AddStatusIB(TLVDissector& tlvDissector, proto_tree *tree, tvbuff_t* tvb)
{
    MATTER_ERROR err;
    proto_tree *statusIBTree;

    VerifyOrExit(tlvDissector.GetType() == kTLVType_Structure, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
    err = tlvDissector.AddSubTreeItem(tree, hf_StatusIB, ett_StatusIB, tvb, statusIBTree);
    SuccessOrExit(err);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {
        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV)
            break;
        SuccessOrExit(err);

        uint64_t tag = tlvDissector.GetTag();
        VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

        switch (TagNumFromTag(tag)) {
        case StatusIB::kTag_Status:
            err = tlvDissector.AddTypedItem(statusIBTree, hf_CommandStatus_Status, tvb);
            break;
        case StatusIB::kTag_ClusterStatus:
            err = tlvDissector.AddTypedItem(statusIBTree, hf_CommandStatus_ClusterStatus, tvb);
            break;
        default:
            err = tlvDissector.AddGenericTLVItem(statusIBTree, hf_ImCommon_Unknown, tvb, false);
            break;
        }
        SuccessOrExit(err);
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

static MATTER_ERROR
AddCommandDataIB(TLVDissector& tlvDissector, proto_tree *tree, tvbuff_t* tvb)
{
    MATTER_ERROR err;
    proto_tree *dataElemTree;

    err = tlvDissector.AddSubTreeItem(tree, hf_CommandDataIB, ett_CommandElem, tvb, dataElemTree);
    SuccessOrExit(err);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {

        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV)
            break;
        SuccessOrExit(err);

        uint64_t tag = tlvDissector.GetTag();
        TLVType type = tlvDissector.GetType();

        VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

        tag = TagNumFromTag(tag);
        switch (tag) {
        case CommandDataIB::kTag_Path:
            VerifyOrExit(type == kTLVType_Path || type == kTLVType_Structure, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = AddNamedPathItem(tlvDissector, dataElemTree, tvb, PathKind::Command);
            SuccessOrExit(err);
            break;
        case CommandDataIB::kTag_Data:
            err = tlvDissector.AddGenericTLVItem(dataElemTree, hf_DataElem_PropertyData, tvb, true);
            SuccessOrExit(err);
            break;
        default:
            err = tlvDissector.AddGenericTLVItem(dataElemTree, hf_ImCommon_Unknown, tvb, false);
            SuccessOrExit(err);
            break;
        }
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

static MATTER_ERROR
AddCommandStatusIB(TLVDissector& tlvDissector, proto_tree *tree, tvbuff_t* tvb)
{
    MATTER_ERROR err;
    proto_tree *statusTree;

    VerifyOrExit(tlvDissector.GetType() == kTLVType_Structure, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
    err = tlvDissector.AddSubTreeItem(tree, hf_CommandStatusIB, ett_CommandElem, tvb, statusTree);
    SuccessOrExit(err);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {
        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV)
            break;
        SuccessOrExit(err);

        uint64_t tag = tlvDissector.GetTag();
        VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

        switch (TagNumFromTag(tag)) {
        case CommandStatusIB::kTag_Path:
            err = AddNamedPathItem(tlvDissector, statusTree, tvb, PathKind::Command);
            break;
        case CommandStatusIB::kTag_Status:
            err = AddStatusIB(tlvDissector, statusTree, tvb);
            break;
        case CommandStatusIB::kTag_Ref:
            err = tlvDissector.AddTypedItem(statusTree, hf_CommandStatus_Ref, tvb);
            break;
        default:
            err = tlvDissector.AddGenericTLVItem(statusTree, hf_ImCommon_Unknown, tvb, false);
            break;
        }
        SuccessOrExit(err);
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

static MATTER_ERROR
AddInvokeResponseIB(TLVDissector& tlvDissector, proto_tree *tree, tvbuff_t* tvb)
{
    MATTER_ERROR err;

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {

        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV)
            break;
        SuccessOrExit(err);

        uint64_t tag = tlvDissector.GetTag();
        TLVType type = tlvDissector.GetType();

        VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

        tag = TagNumFromTag(tag);
        switch (tag) {
        case InvokeResponseIB::kTag_Command:
            VerifyOrExit(type == kTLVType_Structure, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = AddCommandDataIB(tlvDissector, tree, tvb);
            SuccessOrExit(err);
            break;
        case InvokeResponseIB::kTag_Status:
            VerifyOrExit(type == kTLVType_Structure, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = AddCommandStatusIB(tlvDissector, tree, tvb);
            SuccessOrExit(err);
            break;
        default:
            err = tlvDissector.AddGenericTLVItem(tree, hf_ImCommon_Unknown, tvb, false);
            SuccessOrExit(err);
            break;
        }
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

static int
DissectIMStatusResponse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    MATTER_ERROR err;
    const uint8_t *msgData = (const uint8_t *)tvb_memdup(pinfo->pool, tvb, 0, msgInfo.payloadLen);
    TLVDissector tlvDissector;
    int hf_entry;

    proto_item_append_text(proto_tree_get_parent(tree), ": Status Report");

    tlvDissector.Init(msgData, msgInfo.payloadLen);

    err = tlvDissector.Next(kTLVType_Structure, AnonymousTag);
    SuccessOrExit(err);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {

        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV)
            break;
        SuccessOrExit(err);

        uint64_t tag = tlvDissector.GetTag();
        VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
        tag = TagNumFromTag(tag);

        switch (tag)
        {
            case StatusResponse::kTag_Status:
                hf_entry = hf_StatusResponse_Status;
                break;

            case CommonActionInfo::kTag_InteractionModelRevision: 
                hf_entry = hf_ImCommon_Version;
                break;

            default:
                hf_entry = hf_ImCommon_Unknown;
                break;
        }
        SuccessOrExit(err = tlvDissector.AddGenericTLVItem(tree, hf_entry, tvb, false));

    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return msgInfo.payloadLen;
}

static int
DissectIMReadRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    MATTER_ERROR err;
    const uint8_t *msgData = (const uint8_t *)tvb_memdup(pinfo->pool, tvb, 0, msgInfo.payloadLen);
    TLVDissector tlvDissector;
    int hf_entry = -1;

    proto_item_append_text(proto_tree_get_parent(tree), ": Read Request");

    tlvDissector.Init(msgData, msgInfo.payloadLen);

    err = tlvDissector.Next(kTLVType_Structure, AnonymousTag);
    SuccessOrExit(err);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {

        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV)
            break;
        SuccessOrExit(err);

        uint64_t tag = tlvDissector.GetTag();

        VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

        tag = TagNumFromTag(tag);
        switch (tag) {
            case ReadRequest::kTag_AttributeRequests:
                if (tlvDissector.GetType() == kTLVType_Array || tlvDissector.GetType() == kTLVType_Path)
                {
                    hf_entry = -1;
                    err = tlvDissector.AddListItem(tree, hf_ReadRequest_AttributeRequests, ett_SubscribeRequest_PathList, tvb, AddAttributePathItem);
                    SuccessOrExit(err);
                }
                else
                {
                    hf_entry = hf_ReadRequest_AttributeRequests;
                }
                break;

            case ReadRequest::kTag_EventRequests:
                if (tlvDissector.GetType() == kTLVType_Array || tlvDissector.GetType() == kTLVType_Path)
                {
                    hf_entry = -1;
                    err = tlvDissector.AddListItem(tree, hf_ReadRequest_EventRequests, ett_SubscribeRequest_PathList, tvb, AddEventPathItem);
                    SuccessOrExit(err);
                }
                else
                {
                    hf_entry = hf_ReadRequest_EventRequests;
                }
                break;

            case ReadRequest::kTag_EventFilters:
                hf_entry = hf_ReadRequest_EventFilters;
                break;

            case ReadRequest::kTag_IsFabricFiltered:
                hf_entry = hf_ReadRequest_IsFabricFiltered;
                break;

            case ReadRequest::kTag_DataVersionFilters:
                hf_entry = hf_ReadRequest_DataVersionFilters;
                break;

            case CommonActionInfo::kTag_InteractionModelRevision: 
                hf_entry = hf_ImCommon_Version;
                break;

            default:
                hf_entry = hf_ImCommon_Unknown;
                break;
        }
        if (hf_entry != -1)
        {
            SuccessOrExit(err = tlvDissector.AddGenericTLVItem(tree, hf_entry, tvb, false));
        }

    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return msgInfo.payloadLen;
}

static int
DissectIMReportData(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    MATTER_ERROR err;
    const uint8_t *msgData = (const uint8_t *)tvb_memdup(pinfo->pool, tvb, 0, msgInfo.payloadLen);
    TLVDissector tlvDissector;
    int hf_entry = -1;

    proto_item_append_text(proto_tree_get_parent(tree), ": Report Data");

    tlvDissector.Init(msgData, msgInfo.payloadLen);

    err = tlvDissector.Next(kTLVType_Structure, AnonymousTag);
    SuccessOrExit(err);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {

        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV)
            break;
        SuccessOrExit(err);

        uint64_t tag = tlvDissector.GetTag();
        VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
        tag = TagNumFromTag(tag);

        switch (tag) {
            case ReportData::kTag_SubscriptionID:
                hf_entry = hf_ReportData_SubscriptionID;
                break;

            case ReportData::kTag_AttributeReports:
                if (tlvDissector.GetType() == kTLVType_Array || tlvDissector.GetType() == kTLVType_Path)
                {
                    hf_entry = -1;
                    err = tlvDissector.AddListItem(tree, hf_ReportData_AttributeReports, ett_DataElem, tvb, AddAttributeDataIBItem);
                    SuccessOrExit(err);
                }
                else
                {
                    hf_entry = hf_ReportData_AttributeReports;
                }
                break;

            case ReportData::kTag_EventReports:
                if (tlvDissector.GetType() == kTLVType_Array || tlvDissector.GetType() == kTLVType_Path)
                {
                    hf_entry = -1;
                    err = tlvDissector.AddListItem(tree, hf_ReportData_EventReports, ett_DataElem, tvb, AddEventReportIBItem);
                    SuccessOrExit(err);
                }
                else
                {
                    hf_entry = hf_ReportData_EventReports;
                }
                break;

            case ReportData::kTag_MoreChunkedMessages:
                hf_entry = hf_ReportData_MoreChunkedMessages;
                break;

            case ReportData::kTag_SuppressResponse:
                hf_entry = hf_ReportData_SuppressResponse;
                break;

            case CommonActionInfo::kTag_InteractionModelRevision: 
                hf_entry = hf_ImCommon_Version;
                break;

            default:
                hf_entry = hf_ImCommon_Unknown;
                break;
        }
        if (hf_entry != -1)
        {
            SuccessOrExit(err = tlvDissector.AddGenericTLVItem(tree, hf_entry, tvb, false));
        }

    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return msgInfo.payloadLen;
}

static int
DissectIMSubscribeRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    MATTER_ERROR err;
    const uint8_t *msgData = (const uint8_t *)tvb_memdup(pinfo->pool, tvb, 0, msgInfo.payloadLen);
    TLVDissector tlvDissector;
    int hf_entry = -1;

    proto_item_append_text(proto_tree_get_parent(tree), ": Subscribe Request");

    tlvDissector.Init(msgData, msgInfo.payloadLen);

    err = tlvDissector.Next(kTLVType_Structure, AnonymousTag);
    SuccessOrExit(err);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {

        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV)
            break;
        SuccessOrExit(err);

        uint64_t tag = tlvDissector.GetTag();
        VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
        tag = TagNumFromTag(tag);

        switch (tag) {
            case SubscribeRequest::kTag_KeepSubscriptions:
                hf_entry = hf_SubscribeRequest_KeepSubscriptions;
                break;

            case SubscribeRequest::kTag_MinIntervalFloor:
                hf_entry = hf_SubscribeRequest_MinIntervalFloor;
                break;

            case SubscribeRequest::kTag_MaxIntervalCeiling:
                hf_entry = hf_SubscribeRequest_MaxIntervalCeiling;
                break;

            case SubscribeRequest::kTag_AttributeRequests:
                if (tlvDissector.GetType() == kTLVType_Array || tlvDissector.GetType() == kTLVType_Path)
                {
                    hf_entry = -1;
                    err = tlvDissector.AddListItem(tree, hf_SubscribeRequest_AttributeRequests, ett_SubscribeRequest_PathList, tvb, AddAttributePathItem);
                    SuccessOrExit(err);
                }
                else
                {
                    hf_entry = hf_SubscribeRequest_AttributeRequests;
                }
                break;

            case SubscribeRequest::kTag_EventRequests:
                if (tlvDissector.GetType() == kTLVType_Array || tlvDissector.GetType() == kTLVType_Path)
                {
                    hf_entry = -1;
                    err = tlvDissector.AddListItem(tree, hf_SubscribeRequest_EventRequests, ett_SubscribeRequest_PathList, tvb, AddEventPathItem);
                    SuccessOrExit(err);
                }
                else
                {
                    hf_entry = hf_SubscribeRequest_EventRequests;
                }
                break;

            case SubscribeRequest::kTag_EventFilters:
                hf_entry = hf_SubscribeRequest_EventFilters;
                break;

            case SubscribeRequest::kTag_IsFabricFiltered:
                hf_entry = hf_SubscribeRequest_IsFabricFiltered;
                break;

            case SubscribeRequest::kTag_DataVersionFilters:
                hf_entry = hf_SubscribeRequest_DataVersionFilters;
                break;

            case CommonActionInfo::kTag_InteractionModelRevision: 
                hf_entry = hf_ImCommon_Version;
                break;

            default:
                hf_entry = hf_ImCommon_Unknown;
                break;
        }
        if (hf_entry != -1)
        {
            SuccessOrExit(err = tlvDissector.AddGenericTLVItem(tree, hf_entry, tvb, false));
        }

    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return msgInfo.payloadLen;
}

static int
DissectIMSubscribeResponse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    MATTER_ERROR err;
    const uint8_t *msgData = (const uint8_t *)tvb_memdup(pinfo->pool, tvb, 0, msgInfo.payloadLen);
    TLVDissector tlvDissector;
    int hf_entry = -1;

    proto_item_append_text(proto_tree_get_parent(tree), ": Subscribe Response");

    tlvDissector.Init(msgData, msgInfo.payloadLen);

    err = tlvDissector.Next(kTLVType_Structure, AnonymousTag);
    SuccessOrExit(err);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {

        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV)
            break;
        SuccessOrExit(err);

         uint64_t tag = tlvDissector.GetTag();
        VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
        tag = TagNumFromTag(tag);

        switch (tag) {
            case SubscribeResponse::kTag_SubscriptionID:
                hf_entry = hf_SubscribeResponse_SubscriptionID;
                break;

            case SubscribeResponse::kTag_MaxInterval:
                hf_entry = hf_SubscribeResponse_MaxInterval;
                break;

            case CommonActionInfo::kTag_InteractionModelRevision: 
                hf_entry = hf_ImCommon_Version;
                break;

            default:
                hf_entry = hf_ImCommon_Unknown;
                break;
        }
        SuccessOrExit(err = tlvDissector.AddGenericTLVItem(tree, hf_entry, tvb, false));

    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return msgInfo.payloadLen;
}

static int
DissectIMWriteRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    MATTER_ERROR err;
    const uint8_t *msgData = (const uint8_t *)tvb_memdup(pinfo->pool, tvb, 0, msgInfo.payloadLen);
    TLVDissector tlvDissector;
    int hf_entry = -1;

    proto_item_append_text(proto_tree_get_parent(tree), ": Write Request");

    tlvDissector.Init(msgData, msgInfo.payloadLen);

    err = tlvDissector.Next(kTLVType_Structure, AnonymousTag);
    SuccessOrExit(err);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {

        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV)
            break;
        SuccessOrExit(err);

        uint64_t tag = tlvDissector.GetTag();
        VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
        tag = TagNumFromTag(tag);

        switch (tag) {
            case WriteRequest::kTag_SuppressResponse:
                hf_entry = hf_WriteRequest_SuppressResponse;
                break;

            case WriteRequest::kTag_TimedRequest:
                hf_entry = hf_WriteRequest_TimedRequest;
                break;

            case WriteRequest::kTag_WriteRequests:
                if (tlvDissector.GetType() == kTLVType_Array || tlvDissector.GetType() == kTLVType_Path)
                {
                    hf_entry = -1;
                    err = tlvDissector.AddListItem(tree, hf_WriteRequest_WriteRequests, ett_DataElem, tvb, AddAttributeDataIBItem);
                    SuccessOrExit(err);
                }
                else
                {
                    hf_entry = hf_WriteRequest_WriteRequests;
                }
                break;

            case WriteRequest::kTag_MoreChunkedMessages:
                hf_entry = hf_WriteRequest_MoreChunkedMessages;
                break;

            case CommonActionInfo::kTag_InteractionModelRevision: 
                hf_entry = hf_ImCommon_Version;
                break;

            default:
                hf_entry = hf_ImCommon_Unknown;
                break;
        }
        SuccessOrExit(err = tlvDissector.AddGenericTLVItem(tree, hf_entry, tvb, false));

    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return msgInfo.payloadLen;
}

static int
DissectIMWriteResponse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    MATTER_ERROR err;
    const uint8_t *msgData = (const uint8_t *)tvb_memdup(pinfo->pool, tvb, 0, msgInfo.payloadLen);
    TLVDissector tlvDissector;
    int hf_entry = -1;

    proto_item_append_text(proto_tree_get_parent(tree), ": Write Response");

    tlvDissector.Init(msgData, msgInfo.payloadLen);

    err = tlvDissector.Next(kTLVType_Structure, AnonymousTag);
    SuccessOrExit(err);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {

        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV)
            break;
        SuccessOrExit(err);

        uint64_t tag = tlvDissector.GetTag();
        VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
        tag = TagNumFromTag(tag);

        switch (tag) {
            case WriteResponse::kTag_WriteResponses:
                if (tlvDissector.GetType() == kTLVType_Array || tlvDissector.GetType() == kTLVType_Path)
                {
                    hf_entry = -1;
                    err = tlvDissector.AddListItem(tree, hf_WriteResponse_WriteResponses, ett_DataElem, tvb, AddAttributeDataIBItem);
                    SuccessOrExit(err);
                }
                else
                {
                    hf_entry = hf_WriteResponse_WriteResponses;
                }
                break;

            case CommonActionInfo::kTag_InteractionModelRevision: 
                hf_entry = hf_ImCommon_Version;
                break;

            default:
                hf_entry = hf_ImCommon_Unknown;
                break;
        }
        SuccessOrExit(err = tlvDissector.AddGenericTLVItem(tree, hf_entry, tvb, false));
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return msgInfo.payloadLen;
}

static int
DissectIMCommandRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    MATTER_ERROR err;
    const uint8_t *msgData = (const uint8_t *)tvb_memdup(pinfo->pool, tvb, 0, msgInfo.payloadLen);
    TLVDissector tlvDissector;

    proto_item_append_text(proto_tree_get_parent(tree), ": Invoke Command Request");

    tlvDissector.Init(msgData, msgInfo.payloadLen);

    err = tlvDissector.Next(kTLVType_Structure, AnonymousTag);
    SuccessOrExit(err);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {

        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV)
            break;
        SuccessOrExit(err);

        uint64_t tag = tlvDissector.GetTag();
        TLVType type = tlvDissector.GetType();

        VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

        tag = TagNumFromTag(tag);
        switch (tag) {

            case InvokeCommandRequest::kTag_SuppressResponse:
                VerifyOrExit(type == kTLVType_Boolean, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
                err = tlvDissector.AddTypedItem(tree, hf_CommandRequest_SuppressResponse, tvb);
                SuccessOrExit(err);
                break;

            case InvokeCommandRequest::kTag_TimedRequest:
                VerifyOrExit(type == kTLVType_Boolean, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
                err = tlvDissector.AddTypedItem(tree, hf_CommandRequest_TimedRequest, tvb);
                SuccessOrExit(err);
                break;

            case InvokeCommandRequest::kTag_CommandList:
                VerifyOrExit(type == kTLVType_Array, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
                err = tlvDissector.AddListItem(tree, hf_CommandRequest_CommandList, ett_CommandRequest_CommandList, tvb, AddCommandDataIB);
                SuccessOrExit(err);
                break;

            case CommonActionInfo::kTag_InteractionModelRevision:
                SuccessOrExit(err = tlvDissector.AddGenericTLVItem(tree, hf_ImCommon_Version, tvb, false));
                break;

            default:
                SuccessOrExit(err = tlvDissector.AddGenericTLVItem(tree, hf_ImCommon_Unknown, tvb, false));
                break;
        }

    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return msgInfo.payloadLen;
}

static int
DissectIMCommandResponse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    MATTER_ERROR err;
    const uint8_t *msgData = (const uint8_t *)tvb_memdup(pinfo->pool, tvb, 0, msgInfo.payloadLen);
    TLVDissector tlvDissector;
    int hf_entry = -1;

    proto_item_append_text(proto_tree_get_parent(tree), ": Invoke Command Response");

    tlvDissector.Init(msgData, msgInfo.payloadLen);

    err = tlvDissector.Next(kTLVType_Structure, AnonymousTag);
    SuccessOrExit(err);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {

        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV)
            break;
        SuccessOrExit(err);

        uint64_t tag = tlvDissector.GetTag();
        TLVType type = tlvDissector.GetType();
        VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
        tag = TagNumFromTag(tag);

        switch (tag) {

            case InvokeCommandResponse::kTag_SuppressResponse:
                hf_entry = hf_CommandResponse_SuppressResponse;
                break;

            case InvokeCommandResponse::kTag_InvokeResponses:
                VerifyOrExit(type == kTLVType_Array, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
                hf_entry = -1;
                err = tlvDissector.AddListItem(tree, hf_CommandResponse_InvokeResponsesDetail, ett_CommandResponse_InvokeResponseList, tvb, AddInvokeResponseIB);
                SuccessOrExit(err);
                break;

            case CommonActionInfo::kTag_InteractionModelRevision: 
                hf_entry = hf_ImCommon_Version;
                break;

            default:
                hf_entry = hf_ImCommon_Unknown;
                break;
        }
        if (hf_entry != -1) {
            SuccessOrExit(err = tlvDissector.AddGenericTLVItem(tree, hf_entry, tvb, false));
        }
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return msgInfo.payloadLen;
}

static int
DissectIMTimedRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    MATTER_ERROR err;
    const uint8_t *msgData = (const uint8_t *)tvb_memdup(pinfo->pool, tvb, 0, msgInfo.payloadLen);
    TLVDissector tlvDissector;

    proto_item_append_text(proto_tree_get_parent(tree), ": Timed Request");

    tlvDissector.Init(msgData, msgInfo.payloadLen);

    err = tlvDissector.Next(kTLVType_Structure, AnonymousTag);
    SuccessOrExit(err);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {
        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV)
            break;
        SuccessOrExit(err);

        uint64_t tag = tlvDissector.GetTag();
        VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

        switch (TagNumFromTag(tag)) {
        case TimedRequest::kTag_TimeoutMs:
            err = tlvDissector.AddTypedItem(tree, hf_TimedRequest_TimeoutMs, tvb);
            break;
        case CommonActionInfo::kTag_InteractionModelRevision:
            err = tlvDissector.AddGenericTLVItem(tree, hf_ImCommon_Version, tvb, false);
            break;
        default:
            err = tlvDissector.AddGenericTLVItem(tree, hf_ImCommon_Unknown, tvb, false);
            break;
        }
        SuccessOrExit(err);
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return msgInfo.payloadLen;
}

static int
DissectIM(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    const MatterMessageInfo& msgInfo = *(const MatterMessageInfo *)data;

    AddMessageTypeToInfoColumn(pinfo, msgInfo);

    proto_item *top = proto_tree_add_item(tree, proto_im, tvb, 0, -1, ENC_NA);
    proto_tree *im_tree = proto_item_add_subtree(top, ett_im);

    switch (msgInfo.msgType) {
        case kMsgType_StatusResponse:
            return DissectIMStatusResponse(tvb, pinfo, im_tree, msgInfo);
        case kMsgType_ReadRequest:
            return DissectIMReadRequest(tvb, pinfo, im_tree, msgInfo);
        case kMsgType_ReportData:
            return DissectIMReportData(tvb, pinfo, im_tree, msgInfo);
        case kMsgType_SubscribeRequest:
            return DissectIMSubscribeRequest(tvb, pinfo, im_tree, msgInfo);
        case kMsgType_SubscribeResponse:
            return DissectIMSubscribeResponse(tvb, pinfo, im_tree, msgInfo);
        case kMsgType_WriteRequest:
            return DissectIMWriteRequest(tvb, pinfo, im_tree, msgInfo);
        case kMsgType_WriteResponse:
            return DissectIMWriteResponse(tvb, pinfo, im_tree, msgInfo);
        case kMsgType_InvokeRequest:
            return DissectIMCommandRequest(tvb, pinfo, im_tree, msgInfo);
        case kMsgType_InvokeResponse:
            return DissectIMCommandResponse(tvb, pinfo, im_tree, msgInfo);
        case kMsgType_TimedRequest:
            return DissectIMTimedRequest(tvb, pinfo, im_tree, msgInfo);
        default:
            return 0;
    }
}

static bool IMSubscriptionFilter_IsValid(struct _packet_info *pinfo, void *user_data)
{
    MatterMessageRecord *msgRec = MatterMessageTracker::FindMessageRecord(pinfo);
    return msgRec != NULL && msgRec->imSubscription != 0;
}

static gchar* IMSubscriptionFilter_BuildFilterString(struct _packet_info *pinfo, void *user_data)
{
    MatterMessageRecord *msgRec = MatterMessageTracker::FindMessageRecord(pinfo);
    return g_strdup_printf(("im.subscription_id eq 0x%016" PRIX64), msgRec->imSubscription);
}

void
proto_register_matter_im(void)
{
    static hf_register_info hf[] = {

        { &hf_IM_SubscriptionId,
            { "Subscription Id", "im.struct.subscription_id",
            FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        // ===== Common Action Info =====
        { &hf_ImCommon_Version,
            { "InteractionModelRevision", "im.common.revision",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_ImCommon_Unknown,
            { "Unknown", "im.unknown",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_TimedRequest_TimeoutMs,
            { "TimeoutMs", "im.timed_req.timeout_ms",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },

        // ===== Status Response =====
        { &hf_StatusResponse_Status,
            { "Status", "im.status_rsp.status",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        // ===== Read Request =====
        { &hf_ReadRequest_AttributeRequests,
            { "AttributeRequests", "im.read_req.attr_reqs",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_ReadRequest_EventRequests,
            { "EventRequests", "im.read_req.event_reqs",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_ReadRequest_EventFilters,
            { "EventFilters", "im.read_req.event_filters",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_ReadRequest_IsFabricFiltered,
            { "IsFabricFiltered", "im.read_req.is_fabric_filtered",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_ReadRequest_DataVersionFilters,
            { "DataVersionFilters", "im.read_req.data_version_filters",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        // ===== Report Data =====
        { &hf_ReportData_SubscriptionID,
            { "SubscriptionID", "im.report_data.SubscriptionID",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_ReportData_AttributeReports,
            { "AttributeReports", "im.report_data.AttributeReports",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_ReportData_EventReports,
            { "EventReports", "im.report_data.EventReports",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_ReportData_MoreChunkedMessages,
            { "MoreChunkedMessages", "im.report_data.MoreChunkedMessages",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_ReportData_SuppressResponse,
            { "SuppressResponse", "im.report_data.SuppressResponse",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        // ===== Write Request =====
        { &hf_WriteRequest_SuppressResponse,
            { "SuppressResponse", "im.write_req.SuppressResponse",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_WriteRequest_TimedRequest,
            { "TimedRequest", "im.write_req.TimedRequest",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_WriteRequest_WriteRequests,
            { "WriteRequests", "im.write_req.WriteRequests",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_WriteRequest_MoreChunkedMessages,
            { "MoreChunkedMessages", "im.write_req.MoreChunkedMessages",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        // ===== Write Response =====
        { &hf_WriteResponse_WriteResponses,
            { "WriteResponses", "im.write_rsp.WriteResponses",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        // ===== Subscribe Request =====
        { &hf_SubscribeRequest_KeepSubscriptions,
            { "KeepSubscriptions", "im.sub_req.KeepSubscriptions",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_SubscribeRequest_MinIntervalFloor,
            { "MinIntervalFloor", "im.sub_req.MinIntervalFloor",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_SubscribeRequest_MaxIntervalCeiling,
            { "MaxIntervalCeiling", "im.sub_req.MaxIntervalCeiling",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_SubscribeRequest_AttributeRequests,
            { "AttributeRequests", "im.sub_req.AttributeRequests",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_SubscribeRequest_EventRequests,
            { "EventRequests", "im.sub_req.EventRequests",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_SubscribeRequest_EventFilters,
            { "EventFilters", "im.sub_req.EventFilters",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_SubscribeRequest_IsFabricFiltered,
            { "IsFabricFiltered", "im.sub_req.IsFabricFiltered",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_SubscribeRequest_DataVersionFilters,
            { "DataVersionFilters", "im.sub_req.DataVersionFilters",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        // ===== Subscribe Response =====
        { &hf_SubscribeResponse_SubscriptionID,
            { "SubscriptionID", "im.sub_rsp.SubscriptionID",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_SubscribeResponse_MaxInterval,
            { "MaxInterval", "im.sub_rsp.MaxInterval",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        // ===== Command Request =====
        { &hf_CommandRequest_SuppressResponse,
            { "Suppress Response", "im.cmd_req.suppress_response",
            FT_BOOLEAN, 1, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CommandRequest_TimedRequest,
            { "Timed Request", "im.cmd_req.timed_request",
            FT_BOOLEAN, 1, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CommandRequest_CommandList,
            { "Command List", "im.cmd_req.command_list",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CommandRequest_Path,
            { "Property Path", "im.cmd_req.path",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CommandRequest_ExpiryTime,
            { "Expiry Time", "im.cmd_req.expiry_time",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CommandRequest_CommandType,
            { "Command Type", "im.cmd_req.type",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CommandRequest_RequiredVersion,
            { "Required Version", "im.cmd_req.required_version",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CommandRequest_Argument,
            { "Command Argument", "im.cmd_req.argument",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        // ===== Command Response =====
        { &hf_CommandResponse_SuppressResponse,
            { "SuppressResponse", "im.cmd_rsp.SuppressResponse",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CommandResponse_InvokeResponses,
            { "InvokeResponses", "im.cmd_rsp.InvokeResponses",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },


        { &hf_CommandResponse_InvokeResponsesDetail,
            { "InvokeResponses", "im.cmd_rsp.invoke_responses",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CommandResponse_Version,
            { "Version", "im.cmd_rsp.version",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CommandResponse_Result,
            { "Result", "im.cmd_rsp.result",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        // ===== Data Element =====
        { &hf_CommandDataIB,
            { "CommandDataIB", "im.struct.CommandDataIB",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CommandStatusIB,
            { "CommandStatusIB", "im.struct.CommandStatusIB",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_StatusIB,
            { "StatusIB", "im.struct.StatusIB",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CommandStatus_Status,
            { "StatusIB Status", "im.struct.StatusIB.status",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CommandStatus_ClusterStatus,
            { "StatusIB ClusterStatus", "im.struct.StatusIB.cluster_status",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CommandStatus_Ref,
            { "Command Ref", "im.struct.CommandStatusIB.ref",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_DataElem_PropertyPath,
            { "Property Path", "im.struct.CommandPathIB",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_DataElem_PropertyData,
            { "Property Data", "im.struct.CommandDataIB",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

    };

    static gint *ett[] = {
        &ett_im,
        &ett_im_message_container,
        &ett_SubscribeRequest_PathList,
        &ett_SubscribeRequest_LastObservedEventList,
        &ett_SubscribeRequest_VersionList,
        &ett_SubscribeResponse_LastVendedEventList,
        &ett_CommandRequest_CommandList,
        &ett_CommandResponse_InvokeResponseList,
        &ett_CommandElem,
        &ett_DataElem,
        &ett_StatusIB,
    };

    proto_im = proto_register_protocol(
        "Matter Interaction Model Protocol",
        "IM",
        "im"
    );

    proto_register_field_array(proto_im, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_conversation_filter("im", "Matter IM Subscription", IMSubscriptionFilter_IsValid, IMSubscriptionFilter_BuildFilterString, NULL);
}

void
proto_reg_handoff_matter_im(void)
{
    static dissector_handle_t matter_im_handle;

    matter_im_handle = create_dissector_handle(DissectIM, proto_im);
    dissector_add_uint("matter.profile_id", kMatterProfile_InteractionModel, matter_im_handle);
}
