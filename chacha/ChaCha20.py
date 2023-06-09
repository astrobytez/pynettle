#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -----------------------------------
#
# Name:       ChaCha20.py
# Purpose:
#
# Author:     engineer
#
# Created:    23 Oct 2016 2:03 PM
# Copyright:   (c) engineer 2016
# Licence:      MIT
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTUOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
# -----------------------------------
from __future__ import division
from ctypes import create_string_buffer
from hashlib import sha256
from os import urandom

import chacha.api as chacha

# sizes are in octets
CHACHA_KEY_SIZE=32
CHACHA_BLOCK_SIZE=64
CHACHA_NONCE_SIZE=8
CHACHA_NONCE96_SIZE=12


class ChaCha20(object):
    """
    ChaCha20 class exposes the mechanics to encrypt and decrypt using the underlying
    nettle implementation of chacha20
    """

    def __init__(self):
        self.ctx = chacha.chacha_ctx()

    @staticmethod
    def new_nonce():
        # create and set nonce and create context
        nonce = create_string_buffer(CHACHA_NONCE_SIZE)
        nonce.raw = urandom(CHACHA_NONCE_SIZE)
        return nonce

    @staticmethod
    def new_key(p):
        """
        Create a new 32 byte -- 256 bit key.
        The new key is the hash of an input password string.
        """
        p = bytes((ord(i) for i in p))
        k = create_string_buffer(32)
        k.raw = sha256(p).digest()
        return k

    def setup(self, key, nonce):
        """
        # create context and setup nonce
        :param key: the secret key bytes to encrypt with
        :return: None
        """
        assert isinstance(key.raw, bytes)
        assert isinstance(nonce.raw, bytes)
        chacha.chacha_set_key(self.ctx, key)
        chacha.chacha_set_nonce(self.ctx, nonce)

    def encrypt(self, message):
        """
        encrypt message data with given key
        :param message: the message bytes to encrypt
        :return: encrypted output ctypes buffer
        """
        return chacha.chacha20_encrypt(self.ctx, message)

    def decrypt(self, message):
        """
        decrypt message data with given key
        :param message: the message bytes to decrypt
        :return: decrypted output ctypes buffer
        """
        return chacha.chacha20_decrypt(self.ctx, message)
