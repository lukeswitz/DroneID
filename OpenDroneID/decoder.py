#!/usr/bin/env python3
# OpenDroneID (c) B.Kerler 2024.
# Licensed under GPLv3 License
import json

from .Messages.definitions import Statuses, ProtoVersions
from .Messages.msg_authentication import Auth
from .Messages.msg_basicid import IdTypes, UaTypes
from .Messages.msg_locationvector import Coord, SpeedMultipliers, EWDirectionSegments, HeightTypes
from .Messages.msg_operatorid import OperatorIDTypes
from .Messages.msg_selfid import SelfIDTypes
from .Messages.msg_system import Operator
from .utils import structhelper_io


def decode(st, msg_type="unknown"):
    msg_type_field, protocol_version = st.split_4bit()
    msgsize = st.bytes()
    msgcount = st.bytes()
    if msg_type_field != 0xF:
        return None
    msgs = []
    for i in range(msgcount):
        sst = structhelper_io(st.read(msgsize))
        msg_type_field, protocol_version = sst.split_4bit()
        # Add message_type field to all message types
        if msg_type_field == 0:
            id_type, ua_type = sst.split_4bit()
            id = sst.bytes(0x14).rstrip(b"\x00").decode('utf-8')
            reserved = sst.bytes(3)
            msg = {
                "message_type": msg_type,
                "Basic ID": dict(protocol_version=ProtoVersions(0).to_text(protocol_version),
                               id_type=IdTypes(0).to_text(id_type), 
                               ua_type=UaTypes(0).to_text(ua_type), 
                               id=id)
            }
        elif msg_type_field == 1:
            subfields = sst.bytes(1)
            op_status = (subfields >> 4) & 0xF
            height_type = (subfields >> 2) & 0x3
            ew_dir_segment = (subfields >> 1) & 0x1
            speed_multiplier = subfields & 1
            coord = Coord().decode(sst, ew_dir_segment, speed_multiplier)
            msg = {
                "message_type": msg_type,
                "Location/Vector Message": {
                    "protocol_version": ProtoVersions(0).to_text(protocol_version),
                    "op_status": Statuses(0).to_text(op_status),
                    "height_type": HeightTypes(0).to_text(height_type),
                    "ew_dir_segment": EWDirectionSegments(0).to_text(ew_dir_segment),
                    "speed_multiplier": SpeedMultipliers(0).to_text(speed_multiplier)
                }
            }
            for value in coord:
                msg["Location/Vector Message"][value] = coord[value]
        elif msg_type_field == 2:
            auth_data = Auth().decode(sst)
            msg = {
                "message_type": msg_type,
                "Authentication Message": auth_data
            }
            msg["Authentication Message"]["protocol_version"] = ProtoVersions(0).to_text(protocol_version)
        elif msg_type_field == 3:
            text_type = sst.bytes()
            text = sst.bytes(0x17).rstrip(b"\x00").decode('utf-8')
            msg = {
                "message_type": msg_type,
                "Self-ID Message": {
                    "protocol_version": ProtoVersions(0).to_text(protocol_version),
                    "text": text,
                    "text_type": SelfIDTypes(0).to_text(text_type)
                }
            }
        elif msg_type_field == 4:
            operator_data = Operator().decode(sst)
            msg = {
                "message_type": msg_type,
                "System Message": operator_data
            }
            msg["System Message"]["protocol_version"] = ProtoVersions(0).to_text(protocol_version)
        elif msg_type_field == 5:
            operator_id_type = sst.bytes()
            operator_id = sst.bytes(0x14).rstrip(b"\x00").decode('utf-8')
            reserved = sst.bytes(3)
            msg = {
                "message_type": msg_type,
                "Operator ID Message": {
                    "protocol_version": ProtoVersions(0).to_text(protocol_version),
                    "operator_id_type": OperatorIDTypes(0).to_text(operator_id_type),
                    "operator_id": operator_id
                }
            }
        else:
            msg = None
        msgs.append(msg)
    return msgs

def decode_ble(data):
    st = structhelper_io(data)
    st.bytes()  # pkt size
    uuidtype = st.bytes()
    if uuidtype != 0x16:
        return None
    uuid = st.short()
    if uuid != 0xFFFA:
        return None
    appinfo = st.bytes()
    seqno = st.bytes()
    return json.dumps(decode(st, msg_type="bluetooth"))
