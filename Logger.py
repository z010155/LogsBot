import socket
import struct
import threading
import time
from datetime import datetime
import os

class SABot:
    def __init__(self, Username, Password, IP, Port, Commands):
        self.NullByte = struct.pack('B', 0)
        self.BufSize = 4096
        self.InLobby = False
        self.OnlineUsers = {}
        self.OnlineUserMap = {}

        self.NameToIP = {'2DC': '45.76.234.65:1138', 'Paper': '45.76.235.18:1138', 'fineline':  '45.32.193.38:1138', 'U of SA':  '45.32.192.205:1138',
                                      'europe':  '45.63.119.253:1138',  'Mobius':  '45.32.192.102:1138', 'Cartesian':  '45.32.193.38:1139', 'Squaresville': '45.32.193.38:1031'}

        self.IPToName = {'45.76.234.65:1138': '2DC', '45.76.235.18:1138': 'Paper', '45.32.193.38:1138': 'Fineline', '45.32.192.205:1138': 'U of SA',
                                               '45.63.119.253:1138': 'europe', '45.32.192.102:1138': 'Mobius', '45.32.193.38:1139': 'Cartesian', '45.32.193.38:1031': 'Squaresville'}

        self.ServerIP = IP
        self.ServerPort = Port
        self.BotServer = self.IPToName[ '{}:{}'.format(self.ServerIP, self.ServerPort)]

        self.connectToServer(Username, Password, self.ServerIP, self.ServerPort)

    def sendPacket(self, Socket, PacketData, Receive = False):
        Packet = bytes(PacketData, 'utf-8')

        if Socket:
            Socket.send(Packet + self.NullByte)

            if Receive:
                return Socket.recv(self.BufSize).decode('utf-8')
                
    def startKeepAlive(self, TimerSeconds = 20):
        if hasattr(self, 'SocketConn'):
            KeepAliveTimer = threading.Timer(TimerSeconds, self.startKeepAlive)
            KeepAliveTimer.daemon = True
            KeepAliveTimer.start()
            
            self.sendPacket(self.SocketConn, '0')

    def connectionHandler(self):
        Buffer = b''

        while hasattr(self, 'SocketConn'):
            try:
                Buffer += self.SocketConn.recv(self.BufSize)
            except OSError:
                if hasattr(self, 'SocketConn'):
                    self.SocketConn.shutdown(socket.SHUT_RD)
                    self.SocketConn.close()

            if len(Buffer) == 0:
                print('Disconnected')
                break
            elif Buffer.endswith(self.NullByte):
                Receive = Buffer.split(self.NullByte)
                Buffer = b''

                for Data in Receive:
                    Data = Data.decode('utf-8')

                    if Data.startswith('U'):
                        UserID = Data[1:][:3]
                        Username = Data[4:][:20].replace('#', '')

                        self.parseUserData(Data)
                    elif Data.startswith('D'):
                        UserID = Data[1:][:3]
                        Username = self.OnlineUsers[UserID]

                        del self.OnlineUserMap[Username]
                        del self.OnlineUsers[UserID]
                        
                    elif Data.startswith('M'):
                        UserID = Data[1:][:3]

                        self.parseUserMessage(UserID, Data)
                    elif Data.startswith('0g') or Data.startswith('0j'):
                        print('{{Server}}: {}'.format(Data[2:]))
                    elif Data.startswith('093'):
                        print('Secondary login')
                        break
                    elif Data.startswith('0f') or Data.startswith('0e'):
                        Time, Reason = Data[2:].split(';')
                        print('This account has just been banned [Time: {} / Reason: {}]'.format(Time, Reason))
                    elif Data.startswith('0c'):
                        print(Data[2:])
                        
    def connectToServer(self, Username, Password, ServerIP, ServerPort):
        try:
            self.SocketConn = socket.create_connection((ServerIP, ServerPort))
        except Exception as Error:
            print(Error)
            return

        Handshake = self.sendPacket(self.SocketConn, '08HxO9TdCC62Nwln1P', True).strip(self.NullByte.decode('utf-8'))

        if Handshake == '08':
            Credentials = '09{};{}'.format(Username, Password)
            RawData = self.sendPacket(self.SocketConn, Credentials, True).split(self.NullByte.decode('utf-8'))

            for Data in RawData:
                if Data.startswith('A'):
                    self.InLobby = True

                    print('Logged in to {}'.format(self.BotServer))

                    EntryPackets = ['02Z900_', '03_']

                    for Packet in EntryPackets:
                        self.sendPacket(self.SocketConn, Packet)
                        
                    self.startKeepAlive()
                    ConnectionThread = threading.Thread(target=self.connectionHandler)
                    ConnectionThread.start()
                    break
                elif Data == '09':
                    print('Incorrect password')
                    break
                elif Data == '091':
                    print('Currently banned')
                    break
        else:
            print('Server capacity check failed')

    def parseUserData(self, Packet, Password = None):
        StatsString = Packet.replace('\x00', '')
        UserID = StatsString[1:][:3]
        Type = StatsString[:1]

        if Type == 'U':
            if self.InLobby == True:
                Username = StatsString[4:][:20].replace('#', '')
                #StatsString = StatsString[24:]

                self.OnlineUsers[UserID] = Username
                self.OnlineUserMap[Username] = UserID
                
    def parseUserMessage(self, SenderID, Packet):
        if SenderID in self.OnlineUsers:
            Sender = self.OnlineUsers[SenderID]

            NoUseTypes = ['1', '2', '4', '5', '6', '7', '8', '~']
            MessageType = Packet[4:][:1]
            SenderMessage = Packet[5:]
            RawMessage = Packet[1:].replace(SenderID, '')

            if MessageType in NoUseTypes:
                return
            elif MessageType == '9':
                self.write(SenderID, Sender, SenderMessage, False)
            elif MessageType == 'P':
                self.write(SenderID, Sender, SenderMessage, True)
            else:
                self.write(SenderID, Sender, RawMessage, True)
                try:
                    print('[' + Sender + ']: ' + RawMessage)
                except:
                    pass
    def write(self, SenderID, Sender, SenderMessage, Private):
        RespondByPM = (False if Private == False else True)
        Message = SenderMessage.strip()
        MessageCheck = Message.split()
        if not Private:
            try:
                print('[{} in {}] Message: {}'.format(Sender, self.BotServer, SenderMessage))
                Data = open('http://github.com/Michal2SAB/LogsBot/logs.txt', 'a')
                Data.write('[{} in {} on {}] Message: {}\n'.format(Sender, self.BotServer, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), SenderMessage))
                Data.close()
                if Private:
                    print('[PM from {} in {}] Message: {}'.format(Sender, self.BotServer, SenderMessage))
                    Data = open('http://github.com/Michal2SAB/LogsBot/logs.txt', 'a')
                    Data.write('[PM from {} in {} on {}] Message: {}\n'.format(Sender, self.BotServer, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), SenderMessage))
                    Data.close()
            except UnicodeEncodeError:
                print('[UNICODE]')
            except UnicodeDecodeError: 
                print('[{} - "UNICODE"]'.format(Sender))
        
if __name__ == '__main__':
    SABot(os.environ['USER'],  os.environ['PASSWORD'], '45.76.234.65', 1138, True)
