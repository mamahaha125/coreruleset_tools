import argparse
import textwrap
from pathlib import Path

import os
import re
import yaml
from ftw import ruleset, http


logo = """
 ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄        ▄  ▄▄▄▄▄▄▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄  ▄         ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄        ▄  ▄▄▄▄▄▄▄▄▄▄▄
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░▌      ▐░▌▐░░░░░░░░░░░▌     ▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░▌      ▐░▌▐░░░░░░░░░░░▌
▐░█▀▀▀▀▀▀▀▀▀  ▀▀▀▀█░█▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌▐░▌░▌     ▐░▌▐░█▀▀▀▀▀▀▀▀▀      ▐░█▀▀▀▀▀▀▀█░▌▐░▌       ▐░▌ ▀▀▀▀█░█▀▀▀▀ ▐░▌░▌     ▐░▌▐░█▀▀▀▀▀▀▀█░▌
▐░▌               ▐░▌     ▐░▌       ▐░▌▐░▌▐░▌    ▐░▌▐░▌               ▐░▌       ▐░▌▐░▌       ▐░▌     ▐░▌     ▐░▌▐░▌    ▐░▌▐░▌       ▐░▌
▐░█▄▄▄▄▄▄▄▄▄      ▐░▌     ▐░▌       ▐░▌▐░▌ ▐░▌   ▐░▌▐░█▄▄▄▄▄▄▄▄▄      ▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌     ▐░▌     ▐░▌ ▐░▌   ▐░▌▐░▌       ▐░▌
▐░░░░░░░░░░░▌     ▐░▌     ▐░▌       ▐░▌▐░▌  ▐░▌  ▐░▌▐░░░░░░░░░░░▌     ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌     ▐░▌     ▐░▌  ▐░▌  ▐░▌▐░▌       ▐░▌
 ▀▀▀▀▀▀▀▀▀█░▌     ▐░▌     ▐░▌       ▐░▌▐░▌   ▐░▌ ▐░▌▐░█▀▀▀▀▀▀▀▀▀      ▐░█▀▀▀▀█░█▀▀ ▐░█▀▀▀▀▀▀▀█░▌     ▐░▌     ▐░▌   ▐░▌ ▐░▌▐░▌       ▐░▌
          ▐░▌     ▐░▌     ▐░▌       ▐░▌▐░▌    ▐░▌▐░▌▐░▌               ▐░▌     ▐░▌  ▐░▌       ▐░▌     ▐░▌     ▐░▌    ▐░▌▐░▌▐░▌       ▐░▌
 ▄▄▄▄▄▄▄▄▄█░▌     ▐░▌     ▐░█▄▄▄▄▄▄▄█░▌▐░▌     ▐░▐░▌▐░█▄▄▄▄▄▄▄▄▄      ▐░▌      ▐░▌ ▐░▌       ▐░▌ ▄▄▄▄█░█▄▄▄▄ ▐░▌     ▐░▐░▌▐░█▄▄▄▄▄▄▄█░▌
▐░░░░░░░░░░░▌     ▐░▌     ▐░░░░░░░░░░░▌▐░▌      ▐░░▌▐░░░░░░░░░░░▌     ▐░▌       ▐░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░▌      ▐░░▌▐░░░░░░░░░░░▌
 ▀▀▀▀▀▀▀▀▀▀▀       ▀       ▀▀▀▀▀▀▀▀▀▀▀  ▀        ▀▀  ▀▀▀▀▀▀▀▀▀▀▀       ▀         ▀  ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀        ▀▀  ▀▀▀▀▀▀▀▀▀▀▀

                                                                                                                         test WAF rules
"""

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

FIALD = 0

def rules_detailf(rules_dict):
    """
    从yaml文件的数据里构造http请求
    """
    tests_detail = []

    with open(rules_dict, 'r', encoding='utf-8') as f:
        rule_text = yaml.load(f.read(), Loader=yaml.FullLoader)

    tests = rule_text["tests"]
    for req_details in tests:
        rules_detail_set = {"test_title": req_details["test_title"], "测试内容": req_details.get("desc", ""),
                            "请求方式": req_details["stages"][0]["stage"]["input"].get("method", "GET"),
                            "HTTP版本": req_details["stages"][0]["stage"]["input"].get("version", "HTTP/1.1"),
                            "URI": req_details["stages"][0]["stage"]["input"].get("uri", "/"),
                            "请求数据": req_details["stages"][0]["stage"]["input"].get("data", ""),
                            "目标地址": req_details["stages"][0]["stage"]["input"]["dest_addr"],
                            "目标端口": req_details["stages"][0]["stage"]["input"].get("port", 80),
                            "请求头": req_details["stages"][0]["stage"]["input"].get("headers", {}),
                            "协议版本": req_details["stages"][0]["stage"]["input"].get("version", "HTTP/1.1")}
        tests_detail.append(rules_detail_set)

    return tests_detail


def get_filelist(dir, rule_id_list):
    """
    获取规则分类目录
    """
    result = []
    for rule_id in rule_id_list:
        [result.append(os.path.join(dir, file)) for file in os.listdir(dir) if
         re.search("-" + rule_id[0:3] + "-", file)]
    return result


def get_dir(dirs, rule_id_list):
    """
    获取规则目录下的每个yaml文件
    """
    rules_list = []
    for dir in dirs:
        for path, dir_lst, file_lst in os.walk(Path(dir)):
            for dir_name in file_lst:
                for rule_id in rule_id_list:
                    if re.search(rule_id, dir_name):
                        rules_list.append(os.path.join(path, dir_name))
    return rules_list


def send_requests(rule_data, self_data):
    """
    发送规则验证请求
    """
    rule_data["HTTP版本"] = self_data["HTTP版本"]
    # rule_data["test_title"] = self_data["test_title"]
    rule_data["目标地址"] = self_data["目标地址"]
    rule_data["目标端口"] = self_data["目标端口"]
    rule_data["请求头"].update(self_data["请求头"])

    input_data = ruleset.Input(method=rule_data["请求方式"], protocol="http", version=rule_data["HTTP版本"],
                               port=int(rule_data["目标端口"]), uri=rule_data["URI"], dest_addr=rule_data["目标地址"],
                               headers=rule_data["请求头"], data=rule_data["请求数据"])

    http_ua = http.HttpUA()

    http_ua.send_request(input_data)


    print(f'{bcolors.OKGREEN} 测试用例:{rule_data["test_title"]} 目标地址:{rule_data["目标地址"]}  {bcolors.ENDC}',
          end="")
    if http_ua.response_object.status == 403 and http_ua.response_object.headers.get("content-length") == "0":
        print(f'{bcolors.FAIL} WAF拦截 {bcolors.ENDC}')
        global FIALD
        FIALD = FIALD + 1
    else:
        print(f'{bcolors.HEADER} WAF放行 {bcolors.ENDC}')

    http_header, http_body = http_ua.request.split(b"\r\n\r\n")

    if not self_data["requestheader"]:
        print(http_header.decode())
    if not self_data["requestbody"]:
        print("\r\n" + http_body.decode())
        pass
    if not self_data["responseheader"]:
        print(http_ua.response_object.response_line)
        for header_key in http_ua.response_object.headers:
            print(header_key + ":" + http_ua.response_object.headers[header_key])
    if not self_data["responsebody"]:
        print("\r\n" + http_ua.response_object.data.decode())


def main():
    parse = argparse.ArgumentParser(description=logo,
                                    formatter_class=argparse.RawDescriptionHelpFormatter,
                                    epilog=textwrap.dedent('''Example:
        python  -u http://127.0.0.1:80 -r 规则ID(规则id前三位或者全部)
        '''))

    parse.add_argument('-u', '--url', help='    目标URL')
    parse.add_argument('-d', '--data', help='   请求数据')
    parse.add_argument('-H', '--headers', help='    请求头')
    parse.add_argument('-v', '--version', help='   协议版本')
    parse.add_argument('-r', '--rule', help='   规则ID')
    parse.add_argument('-m', '--method', help=' 请求方法')

    ### 日志
    parse.add_argument('-e', '--requestheader', action='store_true', help=' 隐藏请求头')
    parse.add_argument('-b', '--requestbody', action='store_true', help=' 隐藏请求体')
    parse.add_argument('-s', '--responseheader', action='store_true', help=' 隐藏响应头')
    parse.add_argument('-o', '--responsebody', action='store_true', help=' 隐藏响应体')
    parse.add_argument('-n', '--nonereqres', action='store_true', help=' 不打印日志')

    parse.add_argument('-l', '--log', help=' 打印日志')

    # 接收文件和payload参数
    parse.add_argument('-f', '--file', help='   多个规则', type=argparse.FileType('r'))

    args = parse.parse_args()
    # print(args.req_header)
    self_data = {}
    self_data["requestheader"] = False
    self_data["requestbody"] = False
    self_data["responseheader"] = False
    self_data["responsebody"] = False
    # print(args.requestheader)
    if args.requestheader:
        self_data["requestheader"] = True

    if args.requestbody:
        self_data["requestbody"] = True

    if args.responseheader:
        self_data["responseheader"] = True

    if args.responsebody:
        self_data["responsebody"] = True

    if args.nonereqres:
        self_data["requestheader"] = True
        self_data["requestbody"] = True
        self_data["responseheader"] = True
        self_data["responsebody"] = True

    protocol, ip, port = re.search("(\w+)://([^/:]+)(:\d*)?", args.url).group(1), re.search("(\w+)://([^/:]+)(:\d*)?",
                                                                                            args.url).group(
        2), re.search("(\w+)://([^/:]+)(:\d*)?", args.url).group(3)

    # self_data["HTTP版本"] = protocol
    self_data["目标地址"] = ip
    self_data["目标端口"] = port.strip(":")
    self_data["请求头"] = {"Host": ip + port}
    self_data["HTTP版本"] = "HTTP/1.1"
    if args.version:
        self_data["HTTP版本"] = args.version
        # print(self_data["协议版本"])

    current_path = Path(__file__).parents[0]
    print(current_path)
    ddd = get_filelist(current_path, [args.rule])

    list = []
    for i in get_dir(ddd, [args.rule]):
        list.extend(rules_detailf(i))

    verofy_rules = len(list)



    print(verofy_rules)
    for l in list:
        # print(l)
        send_requests(l, self_data)


    print(f'\n{bcolors.OKGREEN} {"测试用例:"}{bcolors.ENDC}', end="")
    print(f'{bcolors.OKGREEN} {str(verofy_rules)}{bcolors.ENDC}')

    print(f'{bcolors.FAIL} {"拦截请求:"} {bcolors.ENDC}', end="")
    print(f'{bcolors.FAIL} {str(FIALD)}{bcolors.ENDC}')

    print(f'{bcolors.OKBLUE} {"放行请求:"} {bcolors.ENDC}', end="")
    print(f'{bcolors.OKBLUE} {str(verofy_rules -  FIALD)}{bcolors.ENDC}')


    print(' 拦截率:   {:.2%}'.format(FIALD/verofy_rules), end="")

if __name__ == "__main__":
    main()
