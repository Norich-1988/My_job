#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import curio


BUFFER_SIZE = 1024

async def echo_server(client, address) -> None:
    print(f'Connection fro {address!r}')
    while True:
        data = await client.recv(BUFFER_SIZE)
        if not data:
            break
        print(f'received {data}')
        await client.sendall(data)
    print('Closed')

if __name__ == '__main__':
    curio.run(curio.tcp_server, 'localhost', 7777, echo_server)

