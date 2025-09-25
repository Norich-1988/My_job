#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import multiprocessing
import typing
import socket

import curio
import curio.ssl
import curio.io

BUFFER_SIZE = 1024

if typing.TYPE_CHECKING:
    from multiprocessing.connection import Connection

def get_socket(pipe: 'Connection') -> typing.Any:
    sock, address = pipe.recv()
    print(f'Sock: {sock}, f{address}')
    return (sock, address)

async def echo_server_async(pipe: 'Connection'):
    async def run_server(pipe: 'Connection', group: curio.TaskGroup) -> None:
        while True:
            sock, address = await curio.run_in_thread(get_socket, pipe)
            await group.spawn(echo_server, sock, address)
            del sock

    async with curio.TaskGroup() as tg:
        await tg.spawn(run_server, pipe, tg)
        # Reap all of the children tasks as they complete
        async for task in tg:
            print(f'Deleting {task!r}')
            task.joined = True
            del task

async def echo_server(iclient, address) -> None:
    print(f'Connection from {address!r}')

    context = curio.ssl.SSLContext(curio.ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('testing.pem', 'testing.key')
    context.set_ciphers('ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384')
    client = await context.wrap_socket(curio.io.Socket(iclient), server_side=True)

    while True:
        data = await client.recv(BUFFER_SIZE)
        if not data:
            break
        print(f'received {data}')
        await client.sendall(data)
    print('Closed')

def main():
    own_conn, child_conn = multiprocessing.Pipe()
    task = multiprocessing.Process(target=curio.run, args=(echo_server_async, child_conn,))
    task.start()

    host, port = 'fake.vdienterprise.com', 7777
    backlog = 100

    sock = None
    try:
        # Wait for socket incoming connections and spread them
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, True)
        except (AttributeError, OSError) as e:
            # log.warning('reuse_port=True option failed', exc_info=True)
            pass

        sock.bind((host, port))
        sock.listen(backlog)
        while True:
            print('Waiting...')
            client, addr = sock.accept()
            print('Sending...')
            own_conn.send((client, addr))

    except Exception:
        pass


    if sock:
        sock.close()

if __name__ == "__main__":
    main()