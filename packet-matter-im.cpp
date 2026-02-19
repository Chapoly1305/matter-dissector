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
#include <algorithm>
#include <string.h>
#include <string>

#include <glib.h>
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/cms.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

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
static int hf_ImCommon_Field = -1;
static int hf_TimedRequest_TimeoutMs = -1;

static int hf_DataElem_PropertyPath = -1;
static int hf_DataElem_PropertyData = -1;

static MATTER_ERROR AddStatusIB(TLVDissector& tlvDissector, proto_tree *tree, tvbuff_t* tvb);

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

struct CommandFieldNameEntry
{
    uint32_t clusterId;
    uint32_t commandId;
    uint32_t tag;
    bool isRequest;
    const char *name;
};

struct EventFieldNameEntry
{
    uint32_t clusterId;
    uint32_t eventId;
    uint32_t tag;
    const char *name;
};

struct AttributeStructFieldNameEntry
{
    uint32_t clusterId;
    uint32_t attributeId;
    uint32_t tag;
    const char *name;
};

struct AttributeEnumValueNameEntry
{
    uint32_t clusterId;
    uint32_t attributeId;
    uint64_t value;
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

const char * GetCommandFieldNameByTag(uint32_t clusterId, uint32_t commandId, uint32_t tag, bool isRequest)
{
    for (size_t i = 0; i < array_length(kCommandFieldNameTable); i++) {
        const auto & entry = kCommandFieldNameTable[i];
        if (entry.clusterId == clusterId && entry.commandId == commandId && entry.tag == tag && entry.isRequest == isRequest) {
            return entry.name;
        }
    }
    return nullptr;
}

const char * GetEventFieldNameByTag(uint32_t clusterId, uint32_t eventId, uint32_t tag)
{
    for (size_t i = 0; i < array_length(kEventFieldNameTable); i++) {
        const auto & entry = kEventFieldNameTable[i];
        if (entry.clusterId == clusterId && entry.eventId == eventId && entry.tag == tag) {
            return entry.name;
        }
    }
    return nullptr;
}

const char * GetAttributeStructFieldNameByTag(uint32_t clusterId, uint32_t attributeId, uint32_t tag)
{
    for (size_t i = 0; i < array_length(kAttributeStructFieldNameTable); i++) {
        const auto & entry = kAttributeStructFieldNameTable[i];
        if (entry.clusterId == clusterId && entry.attributeId == attributeId && entry.tag == tag) {
            return entry.name;
        }
    }
    return nullptr;
}

const char * GetAttributeEnumValueName(uint32_t clusterId, uint32_t attributeId, uint64_t value)
{
    for (size_t i = 0; i < array_length(kAttributeEnumValueNameTable); i++) {
        const auto & entry = kAttributeEnumValueNameTable[i];
        if (entry.clusterId == clusterId && entry.attributeId == attributeId && entry.value == value) {
            return entry.name;
        }
    }
    return nullptr;
}

enum class PathKind
{
    Command,
    Attribute,
    Event,
    Cluster,
};

static MATTER_ERROR AddNamedCommandValue(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb, const char * fieldName);
static MATTER_ERROR AddAttributePathItemAndExtractIds(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb, uint32_t & clusterId,
                                                      uint32_t & attributeId, bool & found);
static MATTER_ERROR AddNamedAttributeStructValue(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb, uint32_t clusterId,
                                                 uint32_t attributeId);
static MATTER_ERROR AddAttributeStatusIBItem(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb);
static MATTER_ERROR AddAttributeReportIBItem(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb);

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
    uint32_t endpointTag = 0xFFFFFFFF;
    uint32_t clusterTag = 0xFFFFFFFF;
    uint32_t itemTag = 0xFFFFFFFF;

    VerifyOrExit(tlvDissector.GetType() == kTLVType_Path || tlvDissector.GetType() == kTLVType_Structure,
                 err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    switch (kind)
    {
    case PathKind::Command:
        endpointTag = 0;
        clusterTag = 1;
        itemTag = 2;
        itemLabel = "Command";
        break;
    case PathKind::Attribute:
        endpointTag = 2;
        clusterTag = 3;
        itemTag = 4;
        itemLabel = "Attribute";
        break;
    case PathKind::Event:
        endpointTag = 1;
        clusterTag = 2;
        itemTag = 3;
        itemLabel = "Event";
        break;
    case PathKind::Cluster:
        endpointTag = 1;
        clusterTag = 2;
        itemTag = 0xFFFFFFFF;
        itemLabel = "Cluster";
        break;
    }

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

        if (!endpointPresent && tagNum == endpointTag)
        {
            endpointId = static_cast<uint32_t>(value);
            endpointPresent = true;
            continue;
        }

        if (!clusterPresent && tagNum == clusterTag)
        {
            clusterId = static_cast<uint32_t>(value);
            clusterPresent = true;
            continue;
        }

        if (!itemPresent && itemTag != 0xFFFFFFFF && tagNum == itemTag)
        {
            itemId = static_cast<uint32_t>(value);
            itemPresent = true;
            continue;
        }
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

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

        if (!endpointPresent && !clusterPresent && !itemPresent)
        {
            ExitNow(err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
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

static MATTER_ERROR AddClusterPathItem(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb)
{
    return AddNamedPathItem(tlvDissector, tree, tvb, PathKind::Cluster);
}

static MATTER_ERROR AddNamedStructItem(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb, PathKind kind)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    proto_tree * itemTree = nullptr;
    bool haveEventPath = false;
    uint32_t eventClusterId = 0;
    uint32_t eventId = 0;

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

        const uint64_t tag = tlvDissector.GetTag();
        const TLVType type = tlvDissector.GetType();
        if (type == kTLVType_Path || type == kTLVType_Structure) {
            if (kind == PathKind::Event) {
                MATTER_ERROR extractErr = MATTER_NO_ERROR;
                bool foundPath = false;
                uint32_t localClusterId = 0;
                uint32_t localEventId = 0;

                extractErr = tlvDissector.EnterContainer();
                if (extractErr == MATTER_NO_ERROR) {
                    while (true) {
                        extractErr = tlvDissector.Next();
                        if (extractErr == MATTER_END_OF_TLV) {
                            extractErr = MATTER_NO_ERROR;
                            break;
                        }
                        if (extractErr != MATTER_NO_ERROR) {
                            break;
                        }

                        if (!IsContextTag(tlvDissector.GetTag()) || tlvDissector.GetType() != kTLVType_UnsignedInteger) {
                            continue;
                        }

                        uint64_t v = 0;
                        extractErr = tlvDissector.Get(v);
                        if (extractErr != MATTER_NO_ERROR) {
                            break;
                        }

                        switch (TagNumFromTag(tlvDissector.GetTag())) {
                        case 2:
                            localClusterId = static_cast<uint32_t>(v);
                            break;
                        case 3:
                            localEventId = static_cast<uint32_t>(v);
                            foundPath = true;
                            break;
                        default:
                            break;
                        }
                    }
                }

                if (extractErr == MATTER_NO_ERROR) {
                    (void) tlvDissector.ExitContainer();
                }

                if (foundPath) {
                    eventClusterId = localClusterId;
                    eventId = localEventId;
                    haveEventPath = true;
                }
            }

            MATTER_ERROR pathErr = AddNamedPathItem(tlvDissector, itemTree, tvb, kind);
            if (pathErr == MATTER_NO_ERROR) {
                continue;
            }
        }

        if (kind == PathKind::Event && haveEventPath && IsContextTag(tag) && TagNumFromTag(tag) == Event::kTag_Data &&
            type == kTLVType_Structure) {
            proto_tree * eventDataTree = nullptr;
            err = tlvDissector.AddSubTreeItem(itemTree, hf_DataElem_PropertyData, ett_DataElem, tvb, eventDataTree);
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

                if (!IsContextTag(tlvDissector.GetTag())) {
                    err = tlvDissector.AddGenericTLVItem(eventDataTree, hf_ImCommon_Unknown, tvb, false);
                    SuccessOrExit(err);
                    continue;
                }

                uint32_t fieldTag = TagNumFromTag(tlvDissector.GetTag());
                const char * fieldName = GetEventFieldNameByTag(eventClusterId, eventId, fieldTag);
                if (fieldName != nullptr) {
                    err = AddNamedCommandValue(tlvDissector, eventDataTree, tvb, fieldName);
                }
                else {
                    err = tlvDissector.AddGenericTLVItem(eventDataTree, hf_ImCommon_Unknown, tvb, false);
                }
                SuccessOrExit(err);
            }

            err = tlvDissector.ExitContainer();
            SuccessOrExit(err);
            continue;
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
    MATTER_ERROR err = MATTER_NO_ERROR;
    proto_tree * itemTree = nullptr;
    bool haveAttributePath = false;
    uint32_t attributeClusterId = 0;
    uint32_t attributeId = 0;

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

        const uint64_t tag = tlvDissector.GetTag();
        if (!IsContextTag(tag)) {
            if (tlvDissector.GetType() == kTLVType_Structure) {
                MATTER_ERROR nestedErr = AddAttributeDataIBItem(tlvDissector, itemTree, tvb);
                if (nestedErr == MATTER_NO_ERROR) {
                    continue;
                }
            }
            err = tlvDissector.AddGenericTLVItem(itemTree, hf_ImCommon_Unknown, tvb, false);
            SuccessOrExit(err);
            continue;
        }

        switch (TagNumFromTag(tag)) {
        case 0: {
            uint64_t value = 0;
            if (tlvDissector.GetType() == kTLVType_UnsignedInteger && tlvDissector.Get(value) == MATTER_NO_ERROR) {
                err = tlvDissector.AddStringItemF(itemTree, hf_ImCommon_Field, tvb, "DataVersion=%llu", (unsigned long long) value);
            }
            else {
                err = tlvDissector.AddGenericTLVItem(itemTree, hf_ImCommon_Unknown, tvb, false);
            }
            SuccessOrExit(err);
            break;
        }
        case 1: {
            MATTER_ERROR pathErr = AddAttributePathItemAndExtractIds(tlvDissector, itemTree, tvb, attributeClusterId, attributeId,
                                                                     haveAttributePath);
            if (pathErr != MATTER_NO_ERROR) {
                err = tlvDissector.AddGenericTLVItem(itemTree, hf_ImCommon_Unknown, tvb, false);
                SuccessOrExit(err);
            }
            break;
        }
        case 2:
            if (haveAttributePath && tlvDissector.GetType() == kTLVType_Structure) {
                err = AddNamedAttributeStructValue(tlvDissector, itemTree, tvb, attributeClusterId, attributeId);
            }
            else if (haveAttributePath && tlvDissector.GetType() == kTLVType_UnsignedInteger) {
                uint64_t value = 0;
                err = tlvDissector.Get(value);
                SuccessOrExit(err);
                const char * enumName = GetAttributeEnumValueName(attributeClusterId, attributeId, value);
                if (enumName != nullptr) {
                    err = tlvDissector.AddStringItemF(itemTree, hf_ImCommon_Field, tvb, "Value=%llu (%s)",
                                                      (unsigned long long) value, enumName);
                }
                else {
                    err = tlvDissector.AddStringItemF(itemTree, hf_ImCommon_Field, tvb, "Value=%llu",
                                                      (unsigned long long) value);
                }
            }
            else if (haveAttributePath && tlvDissector.GetType() == kTLVType_SignedInteger) {
                int64_t value = 0;
                err = tlvDissector.Get(value);
                SuccessOrExit(err);
                if (value >= 0) {
                    const char * enumName = GetAttributeEnumValueName(attributeClusterId, attributeId, static_cast<uint64_t>(value));
                    if (enumName != nullptr) {
                        err = tlvDissector.AddStringItemF(itemTree, hf_ImCommon_Field, tvb, "Value=%lld (%s)",
                                                          (long long) value, enumName);
                    }
                    else {
                        err = tlvDissector.AddStringItemF(itemTree, hf_ImCommon_Field, tvb, "Value=%lld", (long long) value);
                    }
                }
                else {
                    err = tlvDissector.AddStringItemF(itemTree, hf_ImCommon_Field, tvb, "Value=%lld", (long long) value);
                }
            }
            else {
                err = AddNamedCommandValue(tlvDissector, itemTree, tvb, "Value");
            }
            SuccessOrExit(err);
            break;
        default:
            err = tlvDissector.AddGenericTLVItem(itemTree, hf_ImCommon_Unknown, tvb, false);
            SuccessOrExit(err);
            break;
        }
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

static MATTER_ERROR AddEventReportIBItem(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb)
{
    return AddNamedStructItem(tlvDissector, tree, tvb, PathKind::Event);
}

static MATTER_ERROR AddAttributePathItemAndExtractIds(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb, uint32_t & clusterId,
                                                      uint32_t & attributeId, bool & found)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    bool endpointPresent = false;
    bool clusterPresent = false;
    bool attributePresent = false;
    uint32_t endpointId = 0;
    uint32_t localClusterId = 0;
    uint32_t localAttributeId = 0;

    VerifyOrExit(tlvDissector.GetType() == kTLVType_Path || tlvDissector.GetType() == kTLVType_Structure,
                 err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {
        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV) {
            err = MATTER_NO_ERROR;
            break;
        }
        SuccessOrExit(err);

        const uint64_t tag = tlvDissector.GetTag();
        if (!IsContextTag(tag) || tlvDissector.GetType() != kTLVType_UnsignedInteger) {
            continue;
        }

        uint64_t value = 0;
        err = tlvDissector.Get(value);
        SuccessOrExit(err);

        switch (TagNumFromTag(tag)) {
        case 2:
            endpointId = static_cast<uint32_t>(value);
            endpointPresent = true;
            break;
        case 3:
            localClusterId = static_cast<uint32_t>(value);
            clusterPresent = true;
            break;
        case 4:
            localAttributeId = static_cast<uint32_t>(value);
            attributePresent = true;
            break;
        default:
            break;
        }
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

    {
        std::string out;
        if (endpointPresent) {
            char buf[48];
            snprintf(buf, sizeof(buf), "Endpoint=0x%X", endpointId);
            out += buf;
        }

        if (clusterPresent) {
            const char *clusterName = GetClusterNameById(localClusterId);
            char buf[96];
            snprintf(buf, sizeof(buf), "%sCluster=0x%X%s%s", out.empty() ? "" : ", ", localClusterId,
                     (clusterName != nullptr) ? " (" : "", (clusterName != nullptr) ? clusterName : "");
            out += buf;
            if (clusterName != nullptr) {
                out += ")";
            }
        }

        if (attributePresent) {
            const char *attributeName = GetAttributeNameById(localClusterId, localAttributeId);
            char buf[128];
            snprintf(buf, sizeof(buf), "%sAttribute=0x%X%s%s", out.empty() ? "" : ", ", localAttributeId,
                     (attributeName != nullptr) ? " (" : "", (attributeName != nullptr) ? attributeName : "");
            out += buf;
            if (attributeName != nullptr) {
                out += ")";
            }
        }

        if (!endpointPresent && !clusterPresent && !attributePresent) {
            ExitNow(err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
        }

        err = tlvDissector.AddStringItemF(tree, hf_DataElem_PropertyPath, tvb, "%s", out.c_str());
        SuccessOrExit(err);
    }

    if (clusterPresent && attributePresent) {
        clusterId = localClusterId;
        attributeId = localAttributeId;
        found = true;
    }

exit:
    return err;
}

static MATTER_ERROR AddNamedAttributeStructValue(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb, uint32_t clusterId,
                                                 uint32_t attributeId)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    proto_tree * valueTree = nullptr;

    VerifyOrExit(tlvDissector.GetType() == kTLVType_Structure, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
    err = tlvDissector.AddSubTreeItemF(tree, hf_DataElem_PropertyData, ett_DataElem, tvb, valueTree, "Value");
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

        if (!IsContextTag(tlvDissector.GetTag())) {
            err = tlvDissector.AddGenericTLVItem(valueTree, hf_ImCommon_Unknown, tvb, false);
            SuccessOrExit(err);
            continue;
        }

        uint32_t tagNum = TagNumFromTag(tlvDissector.GetTag());
        const char * fieldName = GetAttributeStructFieldNameByTag(clusterId, attributeId, tagNum);
        if (fieldName != nullptr) {
            err = AddNamedCommandValue(tlvDissector, valueTree, tvb, fieldName);
        }
        else {
            err = tlvDissector.AddGenericTLVItem(valueTree, hf_ImCommon_Unknown, tvb, false);
        }
        SuccessOrExit(err);
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

static MATTER_ERROR AddEventFilterIBItem(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    proto_tree * itemTree = nullptr;

    VerifyOrExit(tlvDissector.GetType() == kTLVType_Structure, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
    err = tlvDissector.AddSubTreeItem(tree, hf_ImCommon_Unknown, ett_DataElem, tvb, itemTree);
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

        const uint64_t tag = tlvDissector.GetTag();
        const TLVType type = tlvDissector.GetType();
        if (IsContextTag(tag) && type == kTLVType_UnsignedInteger) {
            uint64_t value = 0;
            err = tlvDissector.Get(value);
            SuccessOrExit(err);
            switch (TagNumFromTag(tag)) {
            case 0:
                err = tlvDissector.AddStringItemF(itemTree, hf_ImCommon_Unknown, tvb, "Node=0x%llX", (unsigned long long) value);
                break;
            case 1:
                err = tlvDissector.AddStringItemF(itemTree, hf_ImCommon_Unknown, tvb, "EventMin=0x%llX", (unsigned long long) value);
                break;
            default:
                err = tlvDissector.AddGenericTLVItem(itemTree, hf_ImCommon_Unknown, tvb, false);
                break;
            }
        }
        else {
            err = tlvDissector.AddGenericTLVItem(itemTree, hf_ImCommon_Unknown, tvb, false);
        }
        SuccessOrExit(err);
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

static MATTER_ERROR AddDataVersionFilterIBItem(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    proto_tree * itemTree = nullptr;

    VerifyOrExit(tlvDissector.GetType() == kTLVType_Structure, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
    err = tlvDissector.AddSubTreeItem(tree, hf_ImCommon_Unknown, ett_DataElem, tvb, itemTree);
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

        const uint64_t tag = tlvDissector.GetTag();
        if (!IsContextTag(tag)) {
            err = tlvDissector.AddGenericTLVItem(itemTree, hf_ImCommon_Unknown, tvb, false);
            SuccessOrExit(err);
            continue;
        }

        switch (TagNumFromTag(tag)) {
        case 0: {
            MATTER_ERROR pathErr = AddClusterPathItem(tlvDissector, itemTree, tvb);
            if (pathErr != MATTER_NO_ERROR) {
                err = tlvDissector.AddGenericTLVItem(itemTree, hf_ImCommon_Unknown, tvb, false);
                SuccessOrExit(err);
            }
            break;
        }
        case 1: {
            uint64_t value = 0;
            if (tlvDissector.GetType() == kTLVType_UnsignedInteger && tlvDissector.Get(value) == MATTER_NO_ERROR) {
                err = tlvDissector.AddStringItemF(itemTree, hf_ImCommon_Unknown, tvb, "DataVersion=%llu", (unsigned long long) value);
            }
            else {
                err = tlvDissector.AddGenericTLVItem(itemTree, hf_ImCommon_Unknown, tvb, false);
            }
            SuccessOrExit(err);
            break;
        }
        default:
            err = tlvDissector.AddGenericTLVItem(itemTree, hf_ImCommon_Unknown, tvb, false);
            SuccessOrExit(err);
            break;
        }
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

enum class AttributeIBKind
{
    Unknown,
    Data,
    Status,
};

static AttributeIBKind DetectAttributeIBKind(TLVDissector & tlvDissector)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    bool hasTag2 = false;
    bool hasTag0Unsigned = false;
    bool hasTag0PathLike = false;
    bool hasTag1PathLike = false;
    bool hasTag1Struct = false;

    if (tlvDissector.GetType() != kTLVType_Structure) {
        return AttributeIBKind::Unknown;
    }

    err = tlvDissector.EnterContainer();
    if (err != MATTER_NO_ERROR) {
        return AttributeIBKind::Unknown;
    }

    while (true) {
        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV) {
            err = MATTER_NO_ERROR;
            break;
        }
        if (err != MATTER_NO_ERROR) {
            break;
        }

        if (!IsContextTag(tlvDissector.GetTag())) {
            continue;
        }

        const uint32_t tagNum = TagNumFromTag(tlvDissector.GetTag());
        const TLVType type = tlvDissector.GetType();

        if (tagNum == 2) {
            hasTag2 = true;
        }
        else if (tagNum == 0) {
            if (type == kTLVType_UnsignedInteger) {
                hasTag0Unsigned = true;
            }
            if (type == kTLVType_Path || type == kTLVType_Structure) {
                hasTag0PathLike = true;
            }
        }
        else if (tagNum == 1) {
            if (type == kTLVType_Path || type == kTLVType_Structure) {
                hasTag1PathLike = true;
            }
            if (type == kTLVType_Structure) {
                hasTag1Struct = true;
            }
        }
    }

    (void) tlvDissector.ExitContainer();

    if (hasTag2 || (hasTag0Unsigned && hasTag1PathLike)) {
        return AttributeIBKind::Data;
    }
    if (hasTag0PathLike && hasTag1Struct) {
        return AttributeIBKind::Status;
    }
    return AttributeIBKind::Unknown;
}

static MATTER_ERROR AddAttributeStatusIBItem(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    proto_tree * itemTree = nullptr;

    VerifyOrExit(tlvDissector.GetType() == kTLVType_Structure, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
    err = tlvDissector.AddSubTreeItem(tree, hf_CommandStatusIB, ett_CommandElem, tvb, itemTree);
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

        const uint64_t tag = tlvDissector.GetTag();
        if (!IsContextTag(tag)) {
            if (tlvDissector.GetType() == kTLVType_Structure) {
                MATTER_ERROR nestedErr = AddAttributeStatusIBItem(tlvDissector, itemTree, tvb);
                if (nestedErr == MATTER_NO_ERROR) {
                    continue;
                }
            }
            err = tlvDissector.AddGenericTLVItem(itemTree, hf_ImCommon_Unknown, tvb, false);
            SuccessOrExit(err);
            continue;
        }

        switch (TagNumFromTag(tag)) {
        case 0: {
            MATTER_ERROR pathErr = AddNamedPathItem(tlvDissector, itemTree, tvb, PathKind::Attribute);
            if (pathErr != MATTER_NO_ERROR) {
                err = tlvDissector.AddGenericTLVItem(itemTree, hf_ImCommon_Unknown, tvb, false);
                SuccessOrExit(err);
            }
            break;
        }
        case 1:
            if (tlvDissector.GetType() == kTLVType_Structure) {
                err = AddStatusIB(tlvDissector, itemTree, tvb);
            }
            else {
                err = tlvDissector.AddGenericTLVItem(itemTree, hf_ImCommon_Unknown, tvb, false);
            }
            SuccessOrExit(err);
            break;
        default:
            err = tlvDissector.AddGenericTLVItem(itemTree, hf_ImCommon_Unknown, tvb, false);
            SuccessOrExit(err);
            break;
        }
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

static MATTER_ERROR AddAttributeReportIBItem(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb)
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

        const uint64_t tag = tlvDissector.GetTag();
        if (!IsContextTag(tag)) {
            if (tlvDissector.GetType() == kTLVType_Structure) {
                MATTER_ERROR nestedErr = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT;
                AttributeIBKind kind = DetectAttributeIBKind(tlvDissector);
                if (kind == AttributeIBKind::Data) {
                    nestedErr = AddAttributeDataIBItem(tlvDissector, itemTree, tvb);
                }
                else if (kind == AttributeIBKind::Status) {
                    nestedErr = AddAttributeStatusIBItem(tlvDissector, itemTree, tvb);
                }
                else {
                    nestedErr = AddAttributeReportIBItem(tlvDissector, itemTree, tvb);
                }
                if (nestedErr == MATTER_NO_ERROR) {
                    continue;
                }
            }
            err = tlvDissector.AddGenericTLVItem(itemTree, hf_ImCommon_Unknown, tvb, false);
            SuccessOrExit(err);
            continue;
        }

        switch (TagNumFromTag(tag)) {
        case 0:
            if (tlvDissector.GetType() == kTLVType_Structure) {
                err = AddAttributeStatusIBItem(tlvDissector, itemTree, tvb);
            }
            else {
                err = tlvDissector.AddGenericTLVItem(itemTree, hf_ImCommon_Unknown, tvb, false);
            }
            SuccessOrExit(err);
            break;
        case 1:
            if (tlvDissector.GetType() == kTLVType_Structure) {
                err = AddAttributeDataIBItem(tlvDissector, itemTree, tvb);
            }
            else {
                err = tlvDissector.AddGenericTLVItem(itemTree, hf_ImCommon_Unknown, tvb, false);
            }
            SuccessOrExit(err);
            break;
        default:
            err = tlvDissector.AddGenericTLVItem(itemTree, hf_ImCommon_Unknown, tvb, false);
            SuccessOrExit(err);
            break;
        }
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

static MATTER_ERROR AddCommandPathItemAndExtractIds(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb, uint32_t & clusterId,
                                                    uint32_t & commandId, bool & found)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    bool endpointPresent = false;
    bool clusterPresent = false;
    bool commandPresent = false;
    uint32_t endpointId = 0;
    uint32_t localClusterId = 0;
    uint32_t localCommandId = 0;

    VerifyOrExit(tlvDissector.GetType() == kTLVType_Path || tlvDissector.GetType() == kTLVType_Structure,
                 err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {
        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV) {
            err = MATTER_NO_ERROR;
            break;
        }
        SuccessOrExit(err);

        const uint64_t tag = tlvDissector.GetTag();
        if (!IsContextTag(tag) || tlvDissector.GetType() != kTLVType_UnsignedInteger) {
            continue;
        }

        uint64_t value = 0;
        err = tlvDissector.Get(value);
        SuccessOrExit(err);

        switch (TagNumFromTag(tag)) {
        case 0:
            endpointId = static_cast<uint32_t>(value);
            endpointPresent = true;
            break;
        case 1:
            localClusterId = static_cast<uint32_t>(value);
            clusterPresent = true;
            break;
        case 2:
            localCommandId = static_cast<uint32_t>(value);
            commandPresent = true;
            break;
        default:
            break;
        }
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

    {
        std::string out;
        if (endpointPresent) {
            char buf[48];
            snprintf(buf, sizeof(buf), "Endpoint=0x%X", endpointId);
            out += buf;
        }

        if (clusterPresent) {
            const char *clusterName = GetClusterNameById(localClusterId);
            char buf[96];
            snprintf(buf, sizeof(buf), "%sCluster=0x%X%s%s", out.empty() ? "" : ", ", localClusterId,
                     (clusterName != nullptr) ? " (" : "", (clusterName != nullptr) ? clusterName : "");
            out += buf;
            if (clusterName != nullptr) {
                out += ")";
            }
        }

        if (commandPresent) {
            const char *commandName = GetCommandNameById(localClusterId, localCommandId);
            char buf[128];
            snprintf(buf, sizeof(buf), "%sCommand=0x%X%s%s", out.empty() ? "" : ", ", localCommandId,
                     (commandName != nullptr) ? " (" : "", (commandName != nullptr) ? commandName : "");
            out += buf;
            if (commandName != nullptr) {
                out += ")";
            }
        }

        if (!endpointPresent && !clusterPresent && !commandPresent) {
            ExitNow(err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
        }

        err = tlvDissector.AddStringItemF(tree, hf_DataElem_PropertyPath, tvb, "%s", out.c_str());
        SuccessOrExit(err);
    }

    if (clusterPresent && commandPresent) {
        clusterId = localClusterId;
        commandId = localCommandId;
        found = true;
    }

exit:
    return err;
}

static bool IsMatterCertificateLikeFieldName(const char * fieldName)
{
    if (fieldName == nullptr) {
        return false;
    }

    const std::string name(fieldName);
    if (name == "CertificationDeclaration") {
        return false;
    }
    return (name.find("Certificate") != std::string::npos) || name == "NOCValue" || name == "ICACValue" || name == "RCACValue";
}

static const char * LookupMatterCertSignatureAlgorithmName(uint64_t value)
{
    switch (value) {
    case 1: return "ECDSAWithSHA256";
    default: return nullptr;
    }
}

static const char * LookupMatterCertPublicKeyAlgorithmName(uint64_t value)
{
    switch (value) {
    case 1: return "ECPublicKey";
    default: return nullptr;
    }
}

static const char * LookupMatterCertCurveName(uint64_t value)
{
    switch (value) {
    case 1: return "prime256v1";
    default: return nullptr;
    }
}

static const char * LookupMatterCertExtendedKeyUsageName(uint64_t value)
{
    switch (value) {
    case 1: return "ServerAuth";
    case 2: return "ClientAuth";
    case 3: return "CodeSigning";
    case 4: return "EmailProtection";
    case 5: return "TimeStamping";
    case 6: return "OCSPSigning";
    default: return nullptr;
    }
}

static MATTER_ERROR AddMatterCertEnumOrRaw(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb, const char * fieldName,
                                           const char * (*lookupName)(uint64_t))
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    uint64_t value = 0;

    if (tlvDissector.GetType() == kTLVType_UnsignedInteger) {
        err = tlvDissector.Get(value);
        SuccessOrExit(err);
    }
    else if (tlvDissector.GetType() == kTLVType_SignedInteger) {
        int64_t signedValue = 0;
        err = tlvDissector.Get(signedValue);
        SuccessOrExit(err);
        if (signedValue < 0) {
            err = tlvDissector.AddStringItemF(tree, hf_ImCommon_Field, tvb, "%s=%" PRId64, fieldName, signedValue);
            SuccessOrExit(err);
            ExitNow();
        }
        value = static_cast<uint64_t>(signedValue);
    }
    else {
        return AddNamedCommandValue(tlvDissector, tree, tvb, fieldName);
    }

    {
        const char * name = (lookupName != nullptr) ? lookupName(value) : nullptr;
        if (name != nullptr) {
            err = tlvDissector.AddStringItemF(tree, hf_ImCommon_Field, tvb, "%s=%" PRIu64 " (%s)", fieldName, value, name);
        }
        else {
            err = tlvDissector.AddStringItemF(tree, hf_ImCommon_Field, tvb, "%s=%" PRIu64, fieldName, value);
        }
        SuccessOrExit(err);
    }

exit:
    return err;
}

static MATTER_ERROR AddMatterCertKeyUsage(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    std::string labels;
    uint64_t value = 0;

    if (tlvDissector.GetType() == kTLVType_UnsignedInteger) {
        err = tlvDissector.Get(value);
        SuccessOrExit(err);
    }
    else if (tlvDissector.GetType() == kTLVType_SignedInteger) {
        int64_t signedValue = 0;
        err = tlvDissector.Get(signedValue);
        SuccessOrExit(err);
        if (signedValue < 0) {
            err = tlvDissector.AddStringItemF(tree, hf_ImCommon_Field, tvb, "KeyUsage=%" PRId64, signedValue);
            SuccessOrExit(err);
            ExitNow();
        }
        value = static_cast<uint64_t>(signedValue);
    }
    else {
        return AddNamedCommandValue(tlvDissector, tree, tvb, "KeyUsage");
    }

    if (value & 0x01) labels += labels.empty() ? "digitalSignature" : "|digitalSignature";
    if (value & 0x02) labels += labels.empty() ? "nonRepudiation" : "|nonRepudiation";
    if (value & 0x04) labels += labels.empty() ? "keyEncipherment" : "|keyEncipherment";
    if (value & 0x08) labels += labels.empty() ? "dataEncipherment" : "|dataEncipherment";
    if (value & 0x10) labels += labels.empty() ? "keyAgreement" : "|keyAgreement";
    if (value & 0x20) labels += labels.empty() ? "keyCertSign" : "|keyCertSign";
    if (value & 0x40) labels += labels.empty() ? "cRLSign" : "|cRLSign";
    if (value & 0x80) labels += labels.empty() ? "encipherOnly" : "|encipherOnly";
    if (value & 0x100) labels += labels.empty() ? "decipherOnly" : "|decipherOnly";

    if (!labels.empty()) {
        err = tlvDissector.AddStringItemF(tree, hf_ImCommon_Field, tvb, "KeyUsage=%" PRIu64 " (%s)", value, labels.c_str());
    }
    else {
        err = tlvDissector.AddStringItemF(tree, hf_ImCommon_Field, tvb, "KeyUsage=%" PRIu64, value);
    }
    SuccessOrExit(err);

exit:
    return err;
}

static const char * GetCertDNAttrNameForIM(uint32_t attrTag)
{
    switch (attrTag) {
    case 0: return "Unspecified";
    case kTag_DNAttrType_CommonName: return "CommonName";
    case kTag_DNAttrType_Surname: return "Surname";
    case kTag_DNAttrType_SerialNumber: return "SerialNumber";
    case kTag_DNAttrType_CountryName: return "CountryName";
    case kTag_DNAttrType_LocalityName: return "LocalityName";
    case kTag_DNAttrType_StateOrProvinceName: return "StateOrProvinceName";
    case kTag_DNAttrType_OrganizationName: return "OrganizationName";
    case kTag_DNAttrType_OrganizationalUnitName: return "OrganizationalUnitName";
    case kTag_DNAttrType_Title: return "Title";
    case kTag_DNAttrType_Name: return "Name";
    case kTag_DNAttrType_GivenName: return "GivenName";
    case kTag_DNAttrType_Initials: return "Initials";
    case kTag_DNAttrType_GenerationQualifier: return "GenerationQualifier";
    case kTag_DNAttrType_DNQualifier: return "DNQualifier";
    case kTag_DNAttrType_Pseudonym: return "Pseudonym";
    case kTag_DNAttrType_DomainComponent: return "DomainComponent";
    case kTag_DNAttrType_MatterDeviceId: return "NodeId";
    case kTag_DNAttrType_MatterServiceEndpointId: return "ServiceEndpointId";
    case kTag_DNAttrType_MatterCAId: return "FabricId";
    case kTag_DNAttrType_MatterSoftwarePublisherId: return "SoftwarePublisherId";
    case 21: return "CASEAuthTag";
    default: return nullptr;
    }
}

static MATTER_ERROR AddDecodedMatterCertificateDN(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb, const char * label)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    proto_tree * dnTree = nullptr;

    VerifyOrExit(tlvDissector.GetType() == kTLVType_Path || tlvDissector.GetType() == kTLVType_Structure,
                 err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
    err = tlvDissector.AddSubTreeItemF(tree, hf_DataElem_PropertyData, ett_DataElem, tvb, dnTree, "%s", label);
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

        if (!IsContextTag(tlvDissector.GetTag())) {
            err = tlvDissector.AddGenericTLVItem(dnTree, hf_ImCommon_Unknown, tvb, false);
            SuccessOrExit(err);
            continue;
        }

        const uint32_t attrTag = TagNumFromTag(tlvDissector.GetTag());
        const uint32_t attrTagBase = attrTag & 0x7F;
        const char * attrName = GetCertDNAttrNameForIM(attrTagBase);
        char dynamicAttrName[32];
        if (attrName == nullptr) {
            snprintf(dynamicAttrName, sizeof(dynamicAttrName), "DNAttr_%u", attrTagBase);
            attrName = dynamicAttrName;
        }
        err = AddNamedCommandValue(tlvDissector, dnTree, tvb, attrName);
        if (err != MATTER_NO_ERROR) {
            err = tlvDissector.AddGenericTLVItem(dnTree, hf_ImCommon_Unknown, tvb, false);
            SuccessOrExit(err);
        }
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

static MATTER_ERROR AddDecodedMatterECDSASignature(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    proto_tree * sigTree = nullptr;

    VerifyOrExit(tlvDissector.GetType() == kTLVType_Structure, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
    err = tlvDissector.AddSubTreeItemF(tree, hf_DataElem_PropertyData, ett_DataElem, tvb, sigTree, "Signature");
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

        if (!IsContextTag(tlvDissector.GetTag())) {
            err = tlvDissector.AddGenericTLVItem(sigTree, hf_ImCommon_Unknown, tvb, false);
            SuccessOrExit(err);
            continue;
        }

        const uint32_t tagNum = TagNumFromTag(tlvDissector.GetTag());
        const char * fieldName = nullptr;
        switch (tagNum) {
        case kTag_ECDSASignature_r:
            fieldName = "r";
            break;
        case kTag_ECDSASignature_s:
            fieldName = "s";
            break;
        default:
            break;
        }

        if (fieldName != nullptr) {
            err = AddNamedCommandValue(tlvDissector, sigTree, tvb, fieldName);
            if (err != MATTER_NO_ERROR) {
                err = tlvDissector.AddGenericTLVItem(sigTree, hf_ImCommon_Unknown, tvb, false);
            }
        }
        else {
            err = tlvDissector.AddGenericTLVItem(sigTree, hf_ImCommon_Unknown, tvb, false);
        }
        SuccessOrExit(err);
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

static MATTER_ERROR AddDecodedMatterCertificateExtensions(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    proto_tree * extTree = nullptr;

    VerifyOrExit(tlvDissector.GetType() == kTLVType_Path || tlvDissector.GetType() == kTLVType_Structure,
                 err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
    err = tlvDissector.AddSubTreeItemF(tree, hf_DataElem_PropertyData, ett_DataElem, tvb, extTree, "Extensions");
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

        const uint64_t tag = tlvDissector.GetTag();
        if (!IsContextTag(tag) && !IsProfileTag(tag)) {
            err = tlvDissector.AddGenericTLVItem(extTree, hf_ImCommon_Unknown, tvb, false);
            SuccessOrExit(err);
            continue;
        }

        switch (TagNumFromTag(tag)) {
        case 1: { // BasicConstraints
            if (tlvDissector.GetType() == kTLVType_Structure) {
                proto_tree * bcTree = nullptr;
                err = tlvDissector.AddSubTreeItemF(extTree, hf_DataElem_PropertyData, ett_DataElem, tvb, bcTree, "BasicConstraints");
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

                    if (!IsContextTag(tlvDissector.GetTag()) && !IsProfileTag(tlvDissector.GetTag())) {
                        err = tlvDissector.AddGenericTLVItem(bcTree, hf_ImCommon_Unknown, tvb, false);
                        SuccessOrExit(err);
                        continue;
                    }

                    const uint32_t innerTag = TagNumFromTag(tlvDissector.GetTag());
                    if (innerTag == 1) {
                        err = AddNamedCommandValue(tlvDissector, bcTree, tvb, "IsCA");
                    }
                    else if (innerTag == 2) {
                        err = AddNamedCommandValue(tlvDissector, bcTree, tvb, "PathLenConstraint");
                    }
                    else {
                        err = tlvDissector.AddGenericTLVItem(bcTree, hf_ImCommon_Unknown, tvb, false);
                    }
                    SuccessOrExit(err);
                }

                err = tlvDissector.ExitContainer();
            }
            else {
                err = AddNamedCommandValue(tlvDissector, extTree, tvb, "BasicConstraints");
            }
            SuccessOrExit(err);
            break;
        }
        case 2:
            err = AddMatterCertKeyUsage(tlvDissector, extTree, tvb);
            SuccessOrExit(err);
            break;
        case 3:
            if (tlvDissector.GetType() == kTLVType_Array || tlvDissector.GetType() == kTLVType_Path) {
                proto_tree * ekuTree = nullptr;
                err = tlvDissector.AddSubTreeItemF(extTree, hf_DataElem_PropertyData, ett_DataElem, tvb, ekuTree, "ExtendedKeyUsage");
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

                    if (tlvDissector.GetType() == kTLVType_UnsignedInteger) {
                        uint64_t usage = 0;
                        err = tlvDissector.Get(usage);
                        SuccessOrExit(err);
                        const char * usageName = LookupMatterCertExtendedKeyUsageName(usage);
                        if (usageName != nullptr) {
                            err = tlvDissector.AddStringItemF(ekuTree, hf_ImCommon_Field, tvb, "Usage=%" PRIu64 " (%s)",
                                                              usage, usageName);
                        }
                        else {
                            err = tlvDissector.AddStringItemF(ekuTree, hf_ImCommon_Field, tvb, "Usage=%" PRIu64, usage);
                        }
                    }
                    else if (tlvDissector.GetType() == kTLVType_SignedInteger) {
                        int64_t usage = 0;
                        err = tlvDissector.Get(usage);
                        SuccessOrExit(err);
                        if (usage >= 0) {
                            const char * usageName = LookupMatterCertExtendedKeyUsageName(static_cast<uint64_t>(usage));
                            if (usageName != nullptr) {
                                err = tlvDissector.AddStringItemF(ekuTree, hf_ImCommon_Field, tvb, "Usage=%" PRId64 " (%s)",
                                                                  usage, usageName);
                            }
                            else {
                                err = tlvDissector.AddStringItemF(ekuTree, hf_ImCommon_Field, tvb, "Usage=%" PRId64, usage);
                            }
                        }
                        else {
                            err = tlvDissector.AddStringItemF(ekuTree, hf_ImCommon_Field, tvb, "Usage=%" PRId64, usage);
                        }
                    }
                    else {
                        err = tlvDissector.AddGenericTLVItem(ekuTree, hf_ImCommon_Unknown, tvb, false);
                    }
                    SuccessOrExit(err);
                }

                err = tlvDissector.ExitContainer();
                SuccessOrExit(err);
            }
            else {
                err = AddNamedCommandValue(tlvDissector, extTree, tvb, "ExtendedKeyUsage");
                SuccessOrExit(err);
            }
            break;
        case 4:
            err = AddNamedCommandValue(tlvDissector, extTree, tvb, "AuthorityKeyIdentifier");
            SuccessOrExit(err);
            break;
        case 5:
            err = AddNamedCommandValue(tlvDissector, extTree, tvb, "SubjectKeyIdentifier");
            SuccessOrExit(err);
            break;
        default:
            err = tlvDissector.AddGenericTLVItem(extTree, hf_ImCommon_Unknown, tvb, false);
            SuccessOrExit(err);
            break;
        }
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

static MATTER_ERROR AddDecodedMatterCertificate(const char * fieldName, const uint8_t * value, uint32_t valueLen, uint32_t valueOffset,
                                                proto_tree * tree, tvbuff_t * tvb)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    TLVDissector certDissector;
    proto_tree * certTree = nullptr;

    certDissector.Init(value, valueLen, valueOffset);
    certDissector.ImplicitProfileId = kMatterProfile_Security;

    err = certDissector.Next(kTLVType_Structure, ProfileTag(kMatterProfile_Security, kTag_MatterCertificate));
    if (err != MATTER_NO_ERROR) {
        certDissector.Init(value, valueLen, valueOffset);
        certDissector.ImplicitProfileId = kMatterProfile_Security;
        err = certDissector.Next(kTLVType_Structure, AnonymousTag);
        SuccessOrExit(err);
    }

    err = certDissector.AddSubTreeItemF(tree, hf_DataElem_PropertyData, ett_DataElem, tvb, certTree, "%s Decoded", fieldName);
    SuccessOrExit(err);

    err = certDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {
        err = certDissector.Next();
        if (err == MATTER_END_OF_TLV) {
            err = MATTER_NO_ERROR;
            break;
        }
        SuccessOrExit(err);

        const uint64_t certTag = certDissector.GetTag();
        if (!IsContextTag(certTag) && !IsProfileTag(certTag)) {
            err = certDissector.AddGenericTLVItem(certTree, hf_ImCommon_Unknown, tvb, false);
            SuccessOrExit(err);
            continue;
        }

        const uint32_t tagNum = TagNumFromTag(certTag);
        switch (tagNum) {
        case 1: // SerialNumber
            err = AddNamedCommandValue(certDissector, certTree, tvb, "SerialNumber");
            break;
        case 2: // SignatureAlgorithm
            err = AddMatterCertEnumOrRaw(certDissector, certTree, tvb, "SignatureAlgorithm",
                                         LookupMatterCertSignatureAlgorithmName);
            break;
        case 3: // Issuer
            err = AddDecodedMatterCertificateDN(certDissector, certTree, tvb, "Issuer");
            break;
        case 4: // NotBefore
            err = AddNamedCommandValue(certDissector, certTree, tvb, "NotBefore");
            break;
        case 5: // NotAfter
            err = AddNamedCommandValue(certDissector, certTree, tvb, "NotAfter");
            break;
        case 6: // Subject
            err = AddDecodedMatterCertificateDN(certDissector, certTree, tvb, "Subject");
            break;
        case 7: // PublicKeyAlgorithm
            err = AddMatterCertEnumOrRaw(certDissector, certTree, tvb, "PublicKeyAlgorithm",
                                         LookupMatterCertPublicKeyAlgorithmName);
            break;
        case 8: // EllipticCurveIdentifier
            err = AddMatterCertEnumOrRaw(certDissector, certTree, tvb, "EllipticCurveIdentifier",
                                         LookupMatterCertCurveName);
            break;
        case 9: // PublicKey
            err = AddNamedCommandValue(certDissector, certTree, tvb, "PublicKey");
            break;
        case 10: // Extensions
            err = AddDecodedMatterCertificateExtensions(certDissector, certTree, tvb);
            break;
        case 11: // Signature
            if (certDissector.GetType() == kTLVType_Structure) {
                err = AddDecodedMatterECDSASignature(certDissector, certTree, tvb);
            }
            else {
                err = AddNamedCommandValue(certDissector, certTree, tvb, "Signature");
            }
            break;
        default:
            err = certDissector.AddGenericTLVItem(certTree, hf_ImCommon_Unknown, tvb, false);
            break;
        }
        SuccessOrExit(err);
    }

    err = certDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

static bool FormatASN1Time(const ASN1_TIME * asn1Time, std::string & out)
{
    if (asn1Time == nullptr) {
        return false;
    }

    BIO * mem = BIO_new(BIO_s_mem());
    if (mem == nullptr) {
        return false;
    }

    if (ASN1_TIME_print(mem, asn1Time) != 1) {
        BIO_free(mem);
        return false;
    }

    char buf[128];
    const int n = BIO_read(mem, buf, static_cast<int>(sizeof(buf) - 1));
    BIO_free(mem);
    if (n <= 0) {
        return false;
    }
    buf[n] = '\0';
    out.assign(buf);
    return true;
}

static MATTER_ERROR AddDecodedX509Certificate(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb, const char * fieldName,
                                              const uint8_t * value, uint32_t valueLen)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    proto_tree * certTree = nullptr;
    X509 * cert = nullptr;
    EVP_PKEY * pubKey = nullptr;
    BIGNUM * serialBn = nullptr;
    char * serialHex = nullptr;

    const unsigned char * p = value;
    cert = d2i_X509(nullptr, &p, static_cast<long>(valueLen));
    if (cert == nullptr) {
        ExitNow(err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
    }

    err = tlvDissector.AddSubTreeItemF(tree, hf_DataElem_PropertyData, ett_DataElem, tvb, certTree, "%s Decoded (X.509)", fieldName);
    SuccessOrExit(err);

    {
        char subjectBuf[512];
        if (X509_NAME_oneline(X509_get_subject_name(cert), subjectBuf, static_cast<int>(sizeof(subjectBuf))) != nullptr) {
            err = tlvDissector.AddStringItemF(certTree, hf_ImCommon_Field, tvb, "Subject=%s", subjectBuf);
            SuccessOrExit(err);
        }
    }

    {
        char issuerBuf[512];
        if (X509_NAME_oneline(X509_get_issuer_name(cert), issuerBuf, static_cast<int>(sizeof(issuerBuf))) != nullptr) {
            err = tlvDissector.AddStringItemF(certTree, hf_ImCommon_Field, tvb, "Issuer=%s", issuerBuf);
            SuccessOrExit(err);
        }
    }

    {
        ASN1_INTEGER * serial = X509_get_serialNumber(cert);
        if (serial != nullptr) {
            serialBn = ASN1_INTEGER_to_BN(serial, nullptr);
            if (serialBn != nullptr) {
                serialHex = BN_bn2hex(serialBn);
                if (serialHex != nullptr) {
                    err = tlvDissector.AddStringItemF(certTree, hf_ImCommon_Field, tvb, "SerialNumber=%s", serialHex);
                    SuccessOrExit(err);
                }
            }
        }
    }

    {
        std::string notBefore;
        if (FormatASN1Time(X509_get0_notBefore(cert), notBefore)) {
            err = tlvDissector.AddStringItemF(certTree, hf_ImCommon_Field, tvb, "NotBefore=%s", notBefore.c_str());
            SuccessOrExit(err);
        }
    }

    {
        std::string notAfter;
        if (FormatASN1Time(X509_get0_notAfter(cert), notAfter)) {
            err = tlvDissector.AddStringItemF(certTree, hf_ImCommon_Field, tvb, "NotAfter=%s", notAfter.c_str());
            SuccessOrExit(err);
        }
    }

    {
        const int sigNid = X509_get_signature_nid(cert);
        const char * sigAlg = OBJ_nid2sn(sigNid);
        if (sigAlg != nullptr) {
            err = tlvDissector.AddStringItemF(certTree, hf_ImCommon_Field, tvb, "SignatureAlgorithm=%s", sigAlg);
            SuccessOrExit(err);
        }
    }

    pubKey = X509_get_pubkey(cert);
    if (pubKey != nullptr) {
        const int keyType = EVP_PKEY_base_id(pubKey);
        const char * keyTypeName = OBJ_nid2sn(keyType);
        if (keyTypeName != nullptr) {
            err = tlvDissector.AddStringItemF(certTree, hf_ImCommon_Field, tvb, "PublicKeyType=%s", keyTypeName);
            SuccessOrExit(err);
        }
        err = tlvDissector.AddStringItemF(certTree, hf_ImCommon_Field, tvb, "PublicKeyBits=%d", EVP_PKEY_bits(pubKey));
        SuccessOrExit(err);
    }

exit:
    if (serialHex != nullptr) {
        OPENSSL_free(serialHex);
    }
    if (serialBn != nullptr) {
        BN_free(serialBn);
    }
    if (pubKey != nullptr) {
        EVP_PKEY_free(pubKey);
    }
    if (cert != nullptr) {
        X509_free(cert);
    }
    return err;
}

static MATTER_ERROR AddDecodedX509CSR(proto_tree * tree, tvbuff_t * tvb, const char * fieldName, const uint8_t * value, uint32_t valueLen,
                                      uint32_t valueOffset, TLVDissector & tlvDissector)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    proto_tree * csrTree = nullptr;
    X509_REQ * req = nullptr;
    EVP_PKEY * pubKey = nullptr;

    const unsigned char * p = value;
    req = d2i_X509_REQ(nullptr, &p, static_cast<long>(valueLen));
    VerifyOrExit(req != nullptr, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

    err = tlvDissector.AddSubTreeItemF(tree, hf_DataElem_PropertyData, ett_DataElem, tvb, csrTree, "%s Decoded (X.509 CSR)", fieldName);
    SuccessOrExit(err);

    {
        char subjectBuf[512];
        if (X509_NAME_oneline(X509_REQ_get_subject_name(req), subjectBuf, static_cast<int>(sizeof(subjectBuf))) != nullptr) {
            err = tlvDissector.AddStringItemF(csrTree, hf_ImCommon_Field, tvb, "Subject=%s", subjectBuf);
            SuccessOrExit(err);
        }
    }

    pubKey = X509_REQ_get_pubkey(req);
    if (pubKey != nullptr) {
        const int keyType = EVP_PKEY_base_id(pubKey);
        const char * keyTypeName = OBJ_nid2sn(keyType);
        if (keyTypeName != nullptr) {
            err = tlvDissector.AddStringItemF(csrTree, hf_ImCommon_Field, tvb, "PublicKeyType=%s", keyTypeName);
            SuccessOrExit(err);
        }
        err = tlvDissector.AddStringItemF(csrTree, hf_ImCommon_Field, tvb, "PublicKeyBits=%d", EVP_PKEY_bits(pubKey));
        SuccessOrExit(err);
    }

    {
        const X509_ALGOR * sigAlg = nullptr;
        X509_REQ_get0_signature(req, nullptr, &sigAlg);
        if (sigAlg != nullptr && sigAlg->algorithm != nullptr) {
            const int sigNid = OBJ_obj2nid(sigAlg->algorithm);
            const char * sigName = OBJ_nid2sn(sigNid);
            if (sigName != nullptr) {
                err = tlvDissector.AddStringItemF(csrTree, hf_ImCommon_Field, tvb, "SignatureAlgorithm=%s", sigName);
                SuccessOrExit(err);
            }
        }
    }

exit:
    (void) valueOffset;
    if (pubKey != nullptr) {
        EVP_PKEY_free(pubKey);
    }
    if (req != nullptr) {
        X509_REQ_free(req);
    }
    return err;
}

static MATTER_ERROR AddDecodedAttestationElements(const uint8_t * value, uint32_t valueLen, uint32_t valueOffset, proto_tree * tree,
                                                  tvbuff_t * tvb, TLVDissector & parentDissector)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    TLVDissector inner;
    proto_tree * elementsTree = nullptr;

    inner.Init(value, valueLen, valueOffset);
    err = inner.Next(kTLVType_Structure, AnonymousTag);
    VerifyOrExit(err == MATTER_NO_ERROR, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

    err = parentDissector.AddSubTreeItemF(tree, hf_DataElem_PropertyData, ett_DataElem, tvb, elementsTree, "AttestationElements Decoded");
    SuccessOrExit(err);

    err = inner.EnterContainer();
    SuccessOrExit(err);

    while (true) {
        err = inner.Next();
        if (err == MATTER_END_OF_TLV) {
            err = MATTER_NO_ERROR;
            break;
        }
        SuccessOrExit(err);

        if (IsContextTag(inner.GetTag())) {
            switch (TagNumFromTag(inner.GetTag())) {
            case 1:
                err = AddNamedCommandValue(inner, elementsTree, tvb, "CertificationDeclaration");
                break;
            case 2:
                err = AddNamedCommandValue(inner, elementsTree, tvb, "AttestationNonce");
                break;
            case 3:
                err = AddNamedCommandValue(inner, elementsTree, tvb, "Timestamp");
                break;
            case 4:
                err = AddNamedCommandValue(inner, elementsTree, tvb, "FirmwareInfo");
                break;
            default:
                err = inner.AddGenericTLVItem(elementsTree, hf_ImCommon_Unknown, tvb, false);
                break;
            }
        }
        else if (IsProfileTag(inner.GetTag())) {
            const uint32_t profileId = ProfileIdFromTag(inner.GetTag());
            const uint32_t tagNum = TagNumFromTag(inner.GetTag());
            if (inner.GetType() == kTLVType_ByteString) {
                err = inner.AddStringItemF(elementsTree, hf_ImCommon_Field, tvb, "VendorReserved Profile=0x%08X Tag=%u [%u bytes]",
                                           profileId, tagNum, inner.GetLength());
            }
            else {
                err = inner.AddStringItemF(elementsTree, hf_ImCommon_Field, tvb, "VendorReserved Profile=0x%08X Tag=%u",
                                           profileId, tagNum);
            }
        }
        else {
            err = inner.AddGenericTLVItem(elementsTree, hf_ImCommon_Unknown, tvb, false);
        }
        SuccessOrExit(err);
    }

    err = inner.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

static MATTER_ERROR AddDecodedNOCSRElements(const uint8_t * value, uint32_t valueLen, uint32_t valueOffset, proto_tree * tree, tvbuff_t * tvb,
                                            TLVDissector & parentDissector)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    TLVDissector inner;
    proto_tree * elementsTree = nullptr;

    inner.Init(value, valueLen, valueOffset);
    err = inner.Next(kTLVType_Structure, AnonymousTag);
    VerifyOrExit(err == MATTER_NO_ERROR, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

    err = parentDissector.AddSubTreeItemF(tree, hf_DataElem_PropertyData, ett_DataElem, tvb, elementsTree, "NOCSRElements Decoded");
    SuccessOrExit(err);

    err = inner.EnterContainer();
    SuccessOrExit(err);

    while (true) {
        err = inner.Next();
        if (err == MATTER_END_OF_TLV) {
            err = MATTER_NO_ERROR;
            break;
        }
        SuccessOrExit(err);

        if (!IsContextTag(inner.GetTag())) {
            err = inner.AddGenericTLVItem(elementsTree, hf_ImCommon_Unknown, tvb, false);
            SuccessOrExit(err);
            continue;
        }

        switch (TagNumFromTag(inner.GetTag())) {
        case 1: // CSR
            err = AddNamedCommandValue(inner, elementsTree, tvb, "CSR");
            SuccessOrExit(err);
            if (inner.GetType() == kTLVType_ByteString && inner.ElemLength() >= inner.GetLength()) {
                const uint8_t * csrValue = nullptr;
                err = inner.GetDataPtr(csrValue);
                SuccessOrExit(err);
                const uint32_t csrLen = inner.GetLength();
                const uint32_t csrOffset = inner.ElemStart() + (inner.ElemLength() - csrLen);
                (void) AddDecodedX509CSR(elementsTree, tvb, "CSR", csrValue, csrLen, csrOffset, parentDissector);
            }
            break;
        case 2:
            err = AddNamedCommandValue(inner, elementsTree, tvb, "CSRNonce");
            break;
        case 3:
            err = AddNamedCommandValue(inner, elementsTree, tvb, "VendorReserved1");
            break;
        case 4:
            err = AddNamedCommandValue(inner, elementsTree, tvb, "VendorReserved2");
            break;
        case 5:
            err = AddNamedCommandValue(inner, elementsTree, tvb, "VendorReserved3");
            break;
        default:
            err = inner.AddGenericTLVItem(elementsTree, hf_ImCommon_Unknown, tvb, false);
            break;
        }
        SuccessOrExit(err);
    }

    err = inner.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

static std::string BytesToHex(const uint8_t * data, size_t len, size_t maxLen = 32)
{
    std::string out;
    const size_t n = std::min(len, maxLen);
    out.reserve(n * 2 + 3);
    for (size_t i = 0; i < n; ++i) {
        char b[3];
        snprintf(b, sizeof(b), "%02X", data[i]);
        out += b;
    }
    if (len > maxLen) {
        out += "...";
    }
    return out;
}

static const char * LookupCertificationTypeName(uint64_t value)
{
    switch (value) {
    case 0: return "DevelopmentAndTest";
    case 1: return "Provisional";
    case 2: return "Official";
    case 3: return "Reserved";
    default: return nullptr;
    }
}

static MATTER_ERROR AddDecodedCertificationDeclarationTLV(const uint8_t * content, uint32_t contentLen, proto_tree * tree, tvbuff_t * tvb,
                                                          TLVDissector & parentDissector)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    TLVDissector reader;
    proto_tree * cdTree = nullptr;

    reader.Init(content, contentLen, 0);
    err = reader.Next(kTLVType_Structure, AnonymousTag);
    VerifyOrExit(err == MATTER_NO_ERROR, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

    err = parentDissector.AddSubTreeItemF(tree, hf_DataElem_PropertyData, ett_DataElem, tvb, cdTree, "CertificationDeclaration Content");
    SuccessOrExit(err);

    err = reader.EnterContainer();
    SuccessOrExit(err);

    while (true) {
        err = reader.Next();
        if (err == MATTER_END_OF_TLV) {
            err = MATTER_NO_ERROR;
            break;
        }
        SuccessOrExit(err);

        if (!IsContextTag(reader.GetTag())) {
            continue;
        }

        const uint32_t tagNum = TagNumFromTag(reader.GetTag());
        switch (tagNum) {
        case 0:
            err = AddNamedCommandValue(reader, cdTree, tvb, "FormatVersion");
            break;
        case 1:
            err = AddNamedCommandValue(reader, cdTree, tvb, "VendorId");
            break;
        case 2:
            if (reader.GetType() == kTLVType_Array) {
                std::string products;
                MATTER_ERROR arrErr = reader.EnterContainer();
                if (arrErr == MATTER_NO_ERROR) {
                    while (true) {
                        arrErr = reader.Next();
                        if (arrErr == MATTER_END_OF_TLV) {
                            arrErr = MATTER_NO_ERROR;
                            break;
                        }
                        if (arrErr != MATTER_NO_ERROR) {
                            break;
                        }

                        uint64_t productId = 0;
                        if (reader.GetType() == kTLVType_UnsignedInteger && reader.Get(productId) == MATTER_NO_ERROR) {
                            char buf[24];
                            snprintf(buf, sizeof(buf), "%s%" PRIu64, products.empty() ? "" : ",", productId);
                            products += buf;
                        }
                    }
                    (void) reader.ExitContainer();
                }
                if (arrErr == MATTER_NO_ERROR) {
                    err = parentDissector.AddStringItemF(cdTree, hf_ImCommon_Field, tvb, "ProductIds=[%s]", products.c_str());
                }
                else {
                    err = parentDissector.AddStringItemF(cdTree, hf_ImCommon_Field, tvb, "ProductIds=[decode error]");
                }
            }
            else {
                err = AddNamedCommandValue(reader, cdTree, tvb, "ProductIds");
            }
            break;
        case 3:
            err = AddNamedCommandValue(reader, cdTree, tvb, "DeviceTypeId");
            break;
        case 4:
            err = AddNamedCommandValue(reader, cdTree, tvb, "CertificateId");
            break;
        case 5:
            err = AddNamedCommandValue(reader, cdTree, tvb, "SecurityLevel");
            break;
        case 6:
            err = AddNamedCommandValue(reader, cdTree, tvb, "SecurityInformation");
            break;
        case 7:
            err = AddNamedCommandValue(reader, cdTree, tvb, "VersionNumber");
            break;
        case 8: {
            uint64_t v = 0;
            if (reader.GetType() == kTLVType_UnsignedInteger && reader.Get(v) == MATTER_NO_ERROR) {
                const char * typeName = LookupCertificationTypeName(v);
                if (typeName != nullptr) {
                    err = parentDissector.AddStringItemF(cdTree, hf_ImCommon_Field, tvb, "CertificationType=%" PRIu64 " (%s)", v,
                                                         typeName);
                }
                else {
                    err = parentDissector.AddStringItemF(cdTree, hf_ImCommon_Field, tvb, "CertificationType=%" PRIu64, v);
                }
            }
            else {
                err = AddNamedCommandValue(reader, cdTree, tvb, "CertificationType");
            }
            break;
        }
        case 9:
            err = AddNamedCommandValue(reader, cdTree, tvb, "DACOriginVendorId");
            break;
        case 10:
            err = AddNamedCommandValue(reader, cdTree, tvb, "DACOriginProductId");
            break;
        case 11:
            if (reader.GetType() == kTLVType_Array) {
                proto_tree * paaTree = nullptr;
                err = parentDissector.AddSubTreeItemF(cdTree, hf_DataElem_PropertyData, ett_DataElem, tvb, paaTree,
                                                      "AuthorizedPAAList");
                SuccessOrExit(err);
                MATTER_ERROR arrErr = reader.EnterContainer();
                if (arrErr == MATTER_NO_ERROR) {
                    uint32_t index = 0;
                    while (true) {
                        arrErr = reader.Next();
                        if (arrErr == MATTER_END_OF_TLV) {
                            arrErr = MATTER_NO_ERROR;
                            break;
                        }
                        if (arrErr != MATTER_NO_ERROR) {
                            break;
                        }
                        if (reader.GetType() == kTLVType_ByteString) {
                            const uint8_t * item = nullptr;
                            if (reader.GetDataPtr(item) == MATTER_NO_ERROR) {
                                std::string hex = BytesToHex(item, reader.GetLength(), 20);
                                err = parentDissector.AddStringItemF(paaTree, hf_ImCommon_Field, tvb, "PAA[%u]=%s", index++, hex.c_str());
                                SuccessOrExit(err);
                            }
                        }
                    }
                    (void) reader.ExitContainer();
                }
                if (arrErr != MATTER_NO_ERROR) {
                    err = parentDissector.AddStringItemF(paaTree, hf_ImCommon_Field, tvb, "AuthorizedPAAList decode failed");
                    SuccessOrExit(err);
                }
            }
            else {
                err = AddNamedCommandValue(reader, cdTree, tvb, "AuthorizedPAAList");
            }
            break;
        default:
            err = parentDissector.AddStringItemF(cdTree, hf_ImCommon_Field, tvb, "UnknownTag[%u]", tagNum);
            break;
        }
        SuccessOrExit(err);
    }

    err = reader.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

static MATTER_ERROR AddDecodedCertificationDeclarationCMS(const uint8_t * value, uint32_t valueLen, proto_tree * tree, tvbuff_t * tvb,
                                                          TLVDissector & parentDissector)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    proto_tree * cmsTree = nullptr;
    CMS_ContentInfo * cms = nullptr;
    STACK_OF(X509) * certs = nullptr;
    const unsigned char * p = value;

    cms = d2i_CMS_ContentInfo(nullptr, &p, static_cast<long>(valueLen));
    VerifyOrExit(cms != nullptr, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

    err = parentDissector.AddSubTreeItemF(tree, hf_DataElem_PropertyData, ett_DataElem, tvb, cmsTree,
                                          "CertificationDeclaration Decoded (CMS)");
    SuccessOrExit(err);

    {
        const ASN1_OBJECT * typeObj = CMS_get0_type(cms);
        if (typeObj != nullptr) {
            char oidBuf[96];
            OBJ_obj2txt(oidBuf, sizeof(oidBuf), typeObj, 1);
            err = parentDissector.AddStringItemF(cmsTree, hf_ImCommon_Field, tvb, "ContentTypeOID=%s", oidBuf);
            SuccessOrExit(err);
        }
    }

    {
        STACK_OF(CMS_SignerInfo) * signerInfos = CMS_get0_SignerInfos(cms);
        const int signerCount = (signerInfos != nullptr) ? sk_CMS_SignerInfo_num(signerInfos) : 0;
        err = parentDissector.AddStringItemF(cmsTree, hf_ImCommon_Field, tvb, "SignerCount=%d", signerCount);
        SuccessOrExit(err);

        if (signerInfos != nullptr && signerCount > 0) {
            CMS_SignerInfo * si = sk_CMS_SignerInfo_value(signerInfos, 0);
            if (si != nullptr) {
                X509_ALGOR * digestAlg = nullptr;
                X509_ALGOR * sigAlg = nullptr;
                CMS_SignerInfo_get0_algs(si, nullptr, nullptr, &digestAlg, &sigAlg);
                if (sigAlg != nullptr && sigAlg->algorithm != nullptr) {
                    const int nid = OBJ_obj2nid(sigAlg->algorithm);
                    const char * name = OBJ_nid2sn(nid);
                    if (name != nullptr) {
                        err = parentDissector.AddStringItemF(cmsTree, hf_ImCommon_Field, tvb, "SignerSignatureAlgorithm=%s", name);
                        SuccessOrExit(err);
                    }
                }

                ASN1_OCTET_STRING * keyId = nullptr;
                CMS_SignerInfo_get0_signer_id(si, &keyId, nullptr, nullptr);
                if (keyId != nullptr && keyId->data != nullptr && keyId->length > 0) {
                    std::string keyIdHex = BytesToHex(keyId->data, static_cast<size_t>(keyId->length), 20);
                    err = parentDissector.AddStringItemF(cmsTree, hf_ImCommon_Field, tvb, "SignerKeyId=%s", keyIdHex.c_str());
                    SuccessOrExit(err);
                }
            }
        }
    }

    certs = CMS_get1_certs(cms);
    {
        const int certCount = (certs != nullptr) ? sk_X509_num(certs) : 0;
        err = parentDissector.AddStringItemF(cmsTree, hf_ImCommon_Field, tvb, "EmbeddedCertificateCount=%d", certCount);
        SuccessOrExit(err);
    }

    {
        ASN1_OCTET_STRING ** content = CMS_get0_content(cms);
        if (content != nullptr && *content != nullptr && (*content)->data != nullptr && (*content)->length > 0) {
            const uint8_t * cdContent = reinterpret_cast<const uint8_t *>((*content)->data);
            const uint32_t cdContentLen = static_cast<uint32_t>((*content)->length);
            err = parentDissector.AddStringItemF(cmsTree, hf_ImCommon_Field, tvb, "ContentLength=%u", cdContentLen);
            SuccessOrExit(err);

            (void) AddDecodedCertificationDeclarationTLV(cdContent, cdContentLen, cmsTree, tvb, parentDissector);
        }
    }

exit:
    if (certs != nullptr) {
        sk_X509_pop_free(certs, X509_free);
    }
    if (cms != nullptr) {
        CMS_ContentInfo_free(cms);
    }
    return err;
}

static MATTER_ERROR AddNamedCommandValue(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb, const char * fieldName)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    TLVType type = tlvDissector.GetType();

    switch (type) {
    case kTLVType_SignedInteger: {
        int64_t value = 0;
        err = tlvDissector.Get(value);
        SuccessOrExit(err);
        err = tlvDissector.AddStringItemF(tree, hf_ImCommon_Field, tvb, "%s=%" PRId64, fieldName, value);
        SuccessOrExit(err);
        break;
    }
    case kTLVType_UnsignedInteger: {
        uint64_t value = 0;
        err = tlvDissector.Get(value);
        SuccessOrExit(err);
        err = tlvDissector.AddStringItemF(tree, hf_ImCommon_Field, tvb, "%s=%" PRIu64, fieldName, value);
        SuccessOrExit(err);
        break;
    }
    case kTLVType_Boolean: {
        bool value = false;
        err = tlvDissector.Get(value);
        SuccessOrExit(err);
        err = tlvDissector.AddStringItemF(tree, hf_ImCommon_Field, tvb, "%s=%s", fieldName, value ? "true" : "false");
        SuccessOrExit(err);
        break;
    }
    case kTLVType_FloatingPointNumber: {
        double value = 0;
        err = tlvDissector.Get(value);
        SuccessOrExit(err);
        err = tlvDissector.AddStringItemF(tree, hf_ImCommon_Field, tvb, "%s=%g", fieldName, value);
        SuccessOrExit(err);
        break;
    }
    case kTLVType_UTF8String: {
        char *value = nullptr;
        err = tlvDissector.DupString(value);
        SuccessOrExit(err);
        err = tlvDissector.AddStringItemF(tree, hf_ImCommon_Field, tvb, "%s=\"%s\"", fieldName, value);
        free(value);
        SuccessOrExit(err);
        break;
    }
    case kTLVType_ByteString: {
        uint32_t valueLen = tlvDissector.GetLength();
        const uint8_t *value = nullptr;
        err = tlvDissector.GetDataPtr(value);
        SuccessOrExit(err);
        err = tlvDissector.AddStringItemF(tree, hf_ImCommon_Field, tvb, "%s=[%u bytes]", fieldName, valueLen);
        SuccessOrExit(err);

        if (valueLen > 0 && strcmp(fieldName, "CertificationDeclaration") == 0) {
            (void) AddDecodedCertificationDeclarationCMS(value, valueLen, tree, tvb, tlvDissector);
        }

        if (valueLen > 0 && IsMatterCertificateLikeFieldName(fieldName) && tlvDissector.ElemLength() >= valueLen) {
            if (AddDecodedX509Certificate(tlvDissector, tree, tvb, fieldName, value, valueLen) == MATTER_NO_ERROR) {
                break;
            }
            const uint32_t valueOffset = tlvDissector.ElemStart() + (tlvDissector.ElemLength() - valueLen);
            (void) AddDecodedMatterCertificate(fieldName, value, valueLen, valueOffset, tree, tvb);
        }

        if (valueLen > 0 && tlvDissector.ElemLength() >= valueLen && strcmp(fieldName, "AttestationElements") == 0) {
            const uint32_t valueOffset = tlvDissector.ElemStart() + (tlvDissector.ElemLength() - valueLen);
            (void) AddDecodedAttestationElements(value, valueLen, valueOffset, tree, tvb, tlvDissector);
        }

        if (valueLen > 0 && tlvDissector.ElemLength() >= valueLen && strcmp(fieldName, "NOCSRElements") == 0) {
            const uint32_t valueOffset = tlvDissector.ElemStart() + (tlvDissector.ElemLength() - valueLen);
            (void) AddDecodedNOCSRElements(value, valueLen, valueOffset, tree, tvb, tlvDissector);
        }
        break;
    }
    case kTLVType_Null:
        err = tlvDissector.AddStringItemF(tree, hf_ImCommon_Field, tvb, "%s=null", fieldName);
        SuccessOrExit(err);
        break;
    case kTLVType_Structure:
    case kTLVType_Array:
    case kTLVType_Path:
        err = tlvDissector.AddStringItemF(tree, hf_ImCommon_Field, tvb, "%s=", fieldName);
        SuccessOrExit(err);
        err = tlvDissector.AddGenericTLVItem(tree, hf_ImCommon_Unknown, tvb, true);
        SuccessOrExit(err);
        break;
    default:
        err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT;
        SuccessOrExit(err);
        break;
    }

exit:
    return err;
}

static MATTER_ERROR AddNamedCommandPayload(TLVDissector & tlvDissector, proto_tree * tree, tvbuff_t * tvb, uint32_t clusterId,
                                           uint32_t commandId, bool isRequest)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    proto_tree *argTree = nullptr;

    VerifyOrExit(tlvDissector.GetType() == kTLVType_Structure, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
    err = tlvDissector.AddSubTreeItemF(tree, hf_CommandRequest_Argument, ett_DataElem, tvb, argTree, "Command Argument");
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

        if (!IsContextTag(tlvDissector.GetTag())) {
            err = tlvDissector.AddGenericTLVItem(argTree, hf_ImCommon_Unknown, tvb, false);
            SuccessOrExit(err);
            continue;
        }

        uint32_t tagNum = TagNumFromTag(tlvDissector.GetTag());
        const char * fieldName = GetCommandFieldNameByTag(clusterId, commandId, tagNum, isRequest);
        if (fieldName != nullptr) {
            err = AddNamedCommandValue(tlvDissector, argTree, tvb, fieldName);
        }
        else {
            err = tlvDissector.AddGenericTLVItem(argTree, hf_ImCommon_Unknown, tvb, false);
        }
        SuccessOrExit(err);
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
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
        if (!IsContextTag(tag)) {
            err = tlvDissector.AddGenericTLVItem(statusIBTree, hf_ImCommon_Unknown, tvb, false);
            SuccessOrExit(err);
            continue;
        }

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
AddCommandDataIB(TLVDissector& tlvDissector, proto_tree *tree, tvbuff_t* tvb, bool decodeNamedPayload, bool isRequestPayload)
{
    MATTER_ERROR err;
    proto_tree *dataElemTree;
    bool haveCommandPath = false;
    uint32_t commandClusterId = 0;
    uint32_t commandId = 0;

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
            err = AddCommandPathItemAndExtractIds(tlvDissector, dataElemTree, tvb, commandClusterId, commandId, haveCommandPath);
            SuccessOrExit(err);
            break;
        case CommandDataIB::kTag_Data:
            if (decodeNamedPayload && haveCommandPath && type == kTLVType_Structure) {
                err = AddNamedCommandPayload(tlvDissector, dataElemTree, tvb, commandClusterId, commandId, isRequestPayload);
            }
            else {
                err = tlvDissector.AddGenericTLVItem(dataElemTree, hf_DataElem_PropertyData, tvb, true);
            }
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
AddCommandDataIBForRequest(TLVDissector& tlvDissector, proto_tree *tree, tvbuff_t* tvb)
{
    return AddCommandDataIB(tlvDissector, tree, tvb, true, true);
}

static MATTER_ERROR
AddCommandDataIBForResponse(TLVDissector& tlvDissector, proto_tree *tree, tvbuff_t* tvb)
{
    return AddCommandDataIB(tlvDissector, tree, tvb, true, false);
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
            err = AddCommandDataIBForResponse(tlvDissector, tree, tvb);
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
                if (tlvDissector.GetType() == kTLVType_Array || tlvDissector.GetType() == kTLVType_Path)
                {
                    hf_entry = -1;
                    err = tlvDissector.AddListItem(tree, hf_ReadRequest_EventFilters, ett_DataElem, tvb, AddEventFilterIBItem);
                    SuccessOrExit(err);
                }
                else
                {
                    hf_entry = hf_ReadRequest_EventFilters;
                }
                break;

            case ReadRequest::kTag_IsFabricFiltered:
                hf_entry = hf_ReadRequest_IsFabricFiltered;
                break;

            case ReadRequest::kTag_DataVersionFilters:
                if (tlvDissector.GetType() == kTLVType_Array || tlvDissector.GetType() == kTLVType_Path)
                {
                    hf_entry = -1;
                    err = tlvDissector.AddListItem(tree, hf_ReadRequest_DataVersionFilters, ett_DataElem, tvb, AddDataVersionFilterIBItem);
                    SuccessOrExit(err);
                }
                else
                {
                    hf_entry = hf_ReadRequest_DataVersionFilters;
                }
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
                    err = tlvDissector.AddListItem(tree, hf_ReportData_AttributeReports, ett_DataElem, tvb, AddAttributeReportIBItem);
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
                if (tlvDissector.GetType() == kTLVType_Array || tlvDissector.GetType() == kTLVType_Path)
                {
                    hf_entry = -1;
                    err = tlvDissector.AddListItem(tree, hf_SubscribeRequest_EventFilters, ett_DataElem, tvb, AddEventFilterIBItem);
                    SuccessOrExit(err);
                }
                else
                {
                    hf_entry = hf_SubscribeRequest_EventFilters;
                }
                break;

            case SubscribeRequest::kTag_IsFabricFiltered:
                hf_entry = hf_SubscribeRequest_IsFabricFiltered;
                break;

            case SubscribeRequest::kTag_DataVersionFilters:
                if (tlvDissector.GetType() == kTLVType_Array || tlvDissector.GetType() == kTLVType_Path)
                {
                    hf_entry = -1;
                    err = tlvDissector.AddListItem(tree, hf_SubscribeRequest_DataVersionFilters, ett_DataElem, tvb, AddDataVersionFilterIBItem);
                    SuccessOrExit(err);
                }
                else
                {
                    hf_entry = hf_SubscribeRequest_DataVersionFilters;
                }
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
                    err = tlvDissector.AddListItem(tree, hf_WriteResponse_WriteResponses, ett_DataElem, tvb, AddAttributeStatusIBItem);
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
                err = tlvDissector.AddListItem(tree, hf_CommandRequest_CommandList, ett_CommandRequest_CommandList, tvb,
                                               AddCommandDataIBForRequest);
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
        { &hf_ImCommon_Field,
            { "Field", "im.field",
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
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_ReadRequest_IsFabricFiltered,
            { "IsFabricFiltered", "im.read_req.is_fabric_filtered",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_ReadRequest_DataVersionFilters,
            { "DataVersionFilters", "im.read_req.data_version_filters",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
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
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_SubscribeRequest_IsFabricFiltered,
            { "IsFabricFiltered", "im.sub_req.IsFabricFiltered",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_SubscribeRequest_DataVersionFilters,
            { "DataVersionFilters", "im.sub_req.DataVersionFilters",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
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
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
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
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
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
