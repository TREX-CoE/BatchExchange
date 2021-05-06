import asyncio
import websockets

class CwAppdWebsocket:
    def __init__(self) -> None:
        self.__host = "localhost"
        self.__port = "8880"


    def connect(self):
        # todo replace "ws://" with "wss://" to enforce TLS
        uri = "ws://" + self.__host + ":" + self.__port
        try:
            self.__websocket = websockets.connect(uri)
        except:
            # todo create error message
            pass


    async def hello(self):
        async with self.__websocket as websocket:
            print(websocket.open)
            name = input("What's your name? ")

            await websocket.send(name)
            print(f"> {name}")

            greeting = await websocket.recv()
            print(f"< {greeting}")


if __name__ == "__main__":
    socket = CwAppdWebsocket()
    socket.connect()
    asyncio.get_event_loop().run_until_complete(socket.hello())
    asyncio.get_event_loop().run_until_complete(socket.hello())