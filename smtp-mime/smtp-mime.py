from getpass import getpass

import argparse
import socket
import base64
import sys
import ssl
import os

context = ssl.create_default_context()


class ServerAnswer:
    def __init__(self, code, msg):
        self.code = code
        self.msg = msg


def get_images(directory):
    images = []
    for r, d, f in os.walk(directory):
        for file_path in f:
            _, extension = os.path.splitext(file_path)
            if extension in ['.jpg']:
                with open(os.path.join(r, file_path), 'rb') as i:
                    images.append(
                        (file_path, base64.b64encode(i.read()).decode('utf-8'))
                    )
    return images


class SMTP:
    def __init__(self, sender, recip, ssl, host, subj, auth, verb, directory):
        self.sender = sender
        self.recipient = recip
        self.ssl = ssl
        self.subject = subj
        self.sender_adress = ''

        host = host.split(':')
        self.host_name = host[0]
        if len(host) == 1:
            self.host_port = 25
        else:
            self.host_port = int(host[1])
        self.auth = auth
        self.verbosel = verb
        self.directory = directory
        self.raw_images = get_images(self.directory)
        self.sock = socket.socket()

        self.send_email()

    def send_email(self):
        sock_old = None
        self.sock.connect((self.host_name, self.host_port))
        self.get_answers()

        self.send_message('EHLO x\n')
        self.get_answers()

        if self.ssl:
            self.send_message('STARTTLS\n')
            self.get_answers()

            sock_old = self.sock

            self.sock = context.wrap_socket(
                self.sock, server_hostname=self.host_name
            )

        username = ''
        if self.auth:
            self.send_message('AUTH LOGIN\n')
            self.get_answers(True)

            print('Login: ', end='')
            self.sender_adress = input()
            username = base64.b64encode(self.sender_adress.encode('utf-8'))\
                .decode('utf-8')
            self.send_message(username + '\n')
            self.get_answers(True)

            password = getpass()
            password = base64.b64encode(password.encode('utf-8'))\
                .decode('utf-8')
            self.send_message(password + '\n')
            self.get_answers()

        self.send_message(f'mail from: <{username}>\n')
        self.get_answers()

        self.send_message(f'rcpt to: <{self.recipient}>\n')
        self.get_answers()

        self.send_message('data\n')
        self.get_answers()

        data = self.create_data()

        self.send_message(''.join(data))
        self.get_answers()

        self.sock.close()

        if sock_old is not None:
            sock_old.close()

    def create_data(self):
        body_header = f'From: =?utf-8?B?'\
                      f'{base64.b64encode(self.sender.encode("utf-8")).decode("utf-8")}'\
                      f'?= <{self.sender_adress}>\n'\
                      f'To: <{self.recipient}>\n'\
                      f'Subject: =?utf-8?B?'\
                      f'{base64.b64encode(self.subject.encode("utf-8")).decode("utf-8")}'\
                      f'?=\n'\
                      f'Content-Type: multipart/mixed; boundary=bound\n\n'
        body_data = []

        body_text_header = '--bound\n' \
                           'Content-Type: text/html; charset=utf-8\n\n'
        body_text_data = 'Some.Text\r\n.\r\nWith.Dots.And.--bound.\n'

        if '\n.\n' in body_text_data:
            body_text_data = body_text_data.replace('\n.\n', '\n..\n')
        if '\r\n.\r\n' in body_text_data:
            body_text_data = body_text_data.replace('\r\n.\r\n', '\r\n..\r\n')

        has_boundary_word = True
        bound = 'bound'
        while has_boundary_word:
            if bound in body_text_data:
                bound += 'd'
            else:
                body_text_header = body_text_header.replace('bound\n', bound + '\n')
                body_header = body_header.replace('bound\n', bound + '\n')
                has_boundary_word = False

        body_data.extend([body_text_header, body_text_data])
        data = self.add_images(body_data, bound)
        data.insert(0, body_header)
        return data

    def add_images(self, data, bound):
        if self.raw_images:
            for image in self.raw_images:
                data.append(
                    f'--{bound}\n'
                    f'Content-Type: image/jpg\n'
                    f'Content-Transfer-Encoding: base64\n'
                    f'Content-disposition:attachment; filename="{image[0]}"\n\n'
                    f'{image[1]}\n'
                )
            data.append(f'--{bound}--')
        data.append('\r\n.\r\n')

        return data
    
    def send_message(self, message):
        self.sock.send(message.encode('utf-8'))

    def get_answers(self, inbase64=False):
        data = self.sock.recv(1024).decode('utf-8').splitlines()
        answers = list(map(lambda x: ServerAnswer(x[:3], x[4:]), data))

        for answer in answers:
            if answer.code[0] in {'4', '5'}:
                print(answer.msg, file=sys.stderr)
                exit(1)
            if self.verbosel:
                if inbase64:
                    print(answer.code,
                          base64.b64decode(answer.msg).decode('utf-8'))
                else:
                    print(answer.code, answer.msg)
                print()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ssl', default=False, type=bool,
                        help='разрешить использование ssl, если сервер '
                             'поддерживает (по умолчанию не использовать)')
    parser.add_argument('-s', '--serve', required=True,
                        help='адрес (или доменное имя) SMTP-сервера в формате '
                             'адрес[:порт] (порт по умолчанию 25)')
    parser.add_argument('-t', '--to', required=True,
                        help='почтовый адрес получателя письма')
    parser.add_argument('-f', '--from', default='<>',
                        help='почтовый адрес отправителя (по умолчанию <>)')
    parser.add_argument('--subject', default='Happy Pictures',
                        help='необязательный параметр, задающий тему письма, '
                             'по умолчанию тема “Happy Pictures”')
    parser.add_argument('--auth', default=False, type=bool,
                        help='запрашивать ли авторизацию (по умолчанию нет), '
                             'если запрашивать, то сделать это после запуска, '
                             'без отображения пароля')
    parser.add_argument('-v', '--verbosel',
                        help='отображение протокола работы (команды и ответы '
                             'на них), за исключением текста письма')
    parser.add_argument('-d', '--directory', default=os.getcwd(),
                        help='каталог с изображениями (по умолчанию $pwd)')
    return parser.parse_args().__dict__


def main():
    args = parse_args()

    SMTP(args['from'],
         args['to'],
         args['ssl'],
         args['serve'],
         args['subject'],
         args['auth'],
         args['verbosel'],
         args['directory'])


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(str(e), file=sys.stderr)
        exit(2)
