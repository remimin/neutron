# -*- coding: utf-8 -*-

class KafkaSendFail(Exception):
    message = _("Cannot send %(msg)s to kafaka server")