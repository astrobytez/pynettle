#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -----------------------------------
#
# Name:       cli.py
# Purpose:
#    
# Author:     engineer
#
# Created:    23 Oct 2016 2:02 PM
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

import click

from ChaCha20 import ChaCha20


def open_file_handles(file_name, extension):
    """
    open input and output file handles to operate on
    :param file_name: the input file to open
    :param extension: the output filename extension
    :return: opened input and output file handles
    """
    try:
        file_handle = open(file_name, 'rb')
    except FileNotFoundError as e:
        print('[-] Error: file not found -- {}'.format(e))
        return

    # configure output file name
    if file_name.endswith('.decrypted'):
        file_name = file_name.replace('.decrypted', '')
    elif file_name.endswith('.encrypted'):
        file_name = file_name.replace('.encrypted', '')
    assert type(extension) is str and len(extension) > 0
    output_file_name = '{}.{}'.format(file_name, extension)

    # create output file
    out_file_handle = open(output_file_name, 'wb')
    return file_handle, out_file_handle


def process_file(in_handle, out_handle, process_function):
    """
    iterates over a file in chunks and calls encrypt/decrypt function that returns respective hash and data
    the processed data is then written to the output file
    :param in_handle: an open file handle
    :param out_handle: an open file handle
    :param process_function: a function to call encrypt/decrypt and return the relevant hash and data
    :return: the completed hash of the relevant file
    """
    hash_list = []
    for data in chunk(in_handle):
        # setup ctypes buffers
        message = create_string_buffer(len(data))
        message.raw = data

        # process data
        data_hash, processed_data = process_function(message)

        # add hash to list
        hash_list.append(data_hash)

        # write data to file
        write_to_file(out_handle, processed_data)
    assert hash_list
    return sha256(b''.join(hash_list)).digest()


def write_to_file(file_handle, data, seek=None):
    """
    write data to a open file handle and seek if required
    :param file_handle: an open file handle
    :param data: data to write to the file
    :param seek: position to write to otherwise write here
    :return: None
    """
    if seek:
        file_handle.seek(seek)
    file_handle.write(data)


def hash_file(ctx, param, value):
    """
    a callback for the eager dummy cli option
    :param ctx: a click context
    :param param: a click parameter
    :param value: a file or bytes literal
    :return: None -- prints the hash value to std-out
    """
    if not value or ctx.resilient_parsing:
        return
    try:
        with open(value, 'rb') as f:
            print(
                '''sha256 of file: {}
{}'''.format(value, sha256(f.read()).hexdigest()))
    except FileNotFoundError:
        data = bytearray(value.encode('utf-8'))
        print('sha256 of {} is: {}'.format(value, sha256(data).hexdigest()))
    ctx.exit()


def chunk(f, chunk_size=int(8192)):
    """
    read chunks of data from a file
    :param f: file handle to read from
    :param chunk_size: the size of the chunks to read
    :return: yields the chunk of data
    """
    while True:
        piece = f.read(chunk_size)
        if not piece:
            break
        else:
            yield piece


@click.group()
def cli():
    pass


@cli.command()
@click.option('--safe', callback=hash_file,
              expose_value=True, is_eager=True,
              help='dont break anything')
@click.password_option()
@click.argument('file_list', nargs=-1)
def encrypt(safe, password, file_list):
    """
    encrypt files using the chacha20 cipher
    :param safe: runs hash_file if enabled
    :param password: the password to use to generate the box
    :param file_list: a list of files to encrypt
    :return: None
    """
    key = ChaCha20.new_key(password)
    box = ChaCha20()

    for file_name in file_list:

        # open the relevant files
        file_handle, out_file_handle = open_file_handles(file_name, extension='encrypted')

        # get the nonce from the box and setup
        nonce = box.nonce.raw
        box.setup(key)

        # a placeholder for the hash
        placeholder = bytearray(32)

        # initialise the header data in output file
        write_to_file(out_file_handle, nonce + placeholder)

        def process_function(x):
            """
            a helper to call encrypt and calculate the hash of the input
            :param x: bytes to encrypt
            :return: the hash of the input bytes and the encrypted bytes
            """
            return sha256(x).digest(), box.encrypt(x).raw

        file_hash = process_file(file_handle,
                                 out_file_handle,
                                 process_function)

        # overwrite the hash placeholder with actual file hash
        write_to_file(out_file_handle, file_hash, 8)

        # close the file handles
        out_file_handle.close()
        file_handle.close()


@cli.command()
@click.option('--safe', callback=hash_file,
              expose_value=True, is_eager=True,
              help='dont break anything')
@click.password_option()
@click.argument('file_list', nargs=-1)
def decrypt(safe, password, file_list):
    """
    decrypt files using the chacha20 cipher
    :param safe: runs hash_file if enabled
    :param password: the password to use to generate the box
    :param file_list: a list of files to decrypt
    :return: None
    """
    key = ChaCha20.new_key(password)
    box = ChaCha20()

    for file_name in file_list:

        # open the relevant files
        file_handle, out_file_handle = open_file_handles(file_name, extension='decrypted')

        # read the nonce and file hash and setup
        box.nonce = create_string_buffer(8)  # read in nonce
        box.nonce.raw = file_handle.read(8)
        extracted_hash = file_handle.read(32)
        box.setup(key)

        def process_function(x):
            """
            a helper to call decrypt and calculate the hash of the output
            :param x: bytes to decrypt
            :return: the hash of the decrypted bytes and the decrypted bytes
            """
            output = box.decrypt(x).raw
            return sha256(output).digest(), output

        file_hash = process_file(file_handle,
                                 out_file_handle,
                                 process_function)

        if not file_hash == extracted_hash:
            print('[-] Error: Message authentication failed')

        # close the file handles
        out_file_handle.close()
        file_handle.close()


if __name__ == '__main__':
    cli()
