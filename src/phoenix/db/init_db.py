# -*- encoding: utf-8 -*-
# Copyright 2016 Vinzor Co.,Ltd.
#
# comment
#
# 4/21/16 bitson : Init

import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

import phoenix.config as cfg
from sqlalchemy import create_engine
from phoenix.db.base import BASE


def init():
    sql_connection = cfg.CONF.database.connection
    if "enterprise" in os.path.dirname(__file__) and os.environ.get('FLASK_CONFIG') == "development":
        sql_connection = sql_connection + "_e"
    engine = create_engine(sql_connection, echo=True)
    BASE.metadata.create_all(engine)