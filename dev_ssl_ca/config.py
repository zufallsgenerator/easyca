#!/usr/bin/env python3

import os

CERTSTRAP = os.environ.get("CERTSTRAP_PATH")

if not CERTSTRAP:
    raise Exception("Please set env variable CERTSTRAP_PATH")
if not os.path.exists(CERTSTRAP):
    raise Exception("CERTSTRAP_PATH invalid: '{}'".format(CERTSTRAP))
if not os.access(CERTSTRAP, os.X_OK):
    raise Exception("Binary '{}' misses executable flag".format(CERTSTRAP))

DEPOT_PATH = os.environ.get("CERTSTRAP_DEPOT")

if not DEPOT_PATH:
    raise Exception("Please set CERTSTRAP_DEPOT env variable")

__all__ = [DEPOT_PATH, CERTSTRAP]
