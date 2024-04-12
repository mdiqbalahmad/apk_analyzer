from androguard.misc import AnalyzeAPK
from androguard.misc import AnalyzeDex
from pathlib import Path
from loguru import logger
from collections import defaultdict


import sys
import json
import subprocess
import hashlib
import os
import re
import argparse


class Analyzer:
    def __init__(self, apkPath, config_file_path, output_dir, debug_mode):
        self.apk_path = apkPath
        self.output_dir = Path(output_dir)
        self.config_file_path = Path(config_file_path)
        self.debug_mode = debug_mode
        self.findings = []
        self.permFindings = []
        self.isDex = self.is_file_dex(apkPath)

        logger.remove(0)
        logger.disable("androguard")

    def is_file_dex(self, apk_path) -> bool:
        dex_headers = [
            b"dex\n035\x00",
            b"dex\n036\x00",
            b"dex\n037\x00",
            b"dex\n038\x00",
            b"dex\n039\x00",
            b"dey\n035\x00",
            b"dey\n036\x00",
            b"dey\n037\x00",
            b"dey\n038\x00",
        ]
        if os.path.exists(apk_path):
            with open(apk_path, "rb") as fp:
                if fp.read()[:8] in dex_headers:
                    return True
                else:
                    return False
        else:
            print("[-] File not found!")
            sys.exit(0)

    def initialize_analyzer(self):
        print("[+] Initialize analyzer..")
        if (self.isDex is True):
            self.a, self.d, self.dx = AnalyzeDex(self.apk_path)
        else:
            self.a, self.d, self.dx = AnalyzeAPK(self.apk_path)

    def analyze(self):
        self.initialize_analyzer()
        self.config_analyze()
        self.check_permissions()
        if self.decompile_apk():
            self.check_methods_usage()
        # self.printMethods()

    def check_permissions(self):
        if self.isDex is False:
            permissionList = self.a.get_permissions()
            for apk_perm in permissionList:
                apk_perm = apk_perm.split(".")[-1]
                for config_perm in self.permissionList:
                    if apk_perm == config_perm:
                        finding = "{} | {}".format(
                            apk_perm, self.permissionList[apk_perm]
                        )
                        (
                            self.permFindings.append(finding)
                            if finding not in self.permFindings
                            else self.permFindings
                        )
        else:
            print("[*] DEX files not have Androidmanifest.xml file!")

    def check_methods_usage(self):
        for method in self.method_signatures:
            className = self.method_signatures[method]["className"]
            allFunctions = self.method_signatures[method]["functions"]
            for functions in allFunctions:
                for function in functions:
                    for methodNames in functions[function]["methodNames"]:
                        self.current_methodLen = len(methodNames)
                        for methodName in methodNames:
                            finding = self.method_hunter(
                                function, functions, method,
                                className, methodName
                            )

                    if finding is not None and self.current_methodLen == 0:
                        (
                            self.findings.append(finding)
                            if finding not in self.findings
                            else self.findings
                        )

    def method_hunter(self, function, functions, method,
                      className, methodName) -> str:
        finding = None
        findings = self.dx.find_methods(classname=className,
                                        methodname=methodName)
        for find in findings:
            if function in str(find.get_method()):
                ex_founded = False
                self.current_methodLen -= 1
                search_invoke = className + ";->" + function
                results = self.parse_smali_for_method(search_invoke)
                if results is not None:
                    assignments = functions[function]["assignments"]
                    for assignment in assignments:
                        if (len(assignment)):
                            ex_founded = True
                            res_assignment = results["assignments"]
                            for key in assignment:
                                value = assignment[key]
                                for res_key in res_assignment:
                                    res_values = res_assignment[res_key]
                                    for res_value in res_values:
                                        if key == res_key:
                                            print(value, res_value)
                                            if value == res_value:
                                                ex_founded = False

                        if len(results) != 0 and ex_founded is False:
                            normal_results = "None"
                            if not self.debug_mode and \
                                    len(results["assignments"]) > 0:
                                normal_results = "("
                                for var in results["assignments"]:
                                    normal_results += "{}:\"{}\", ".format(
                                        var,
                                        results["assignments"][var]
                                    )
                                normal_results = normal_results[:-2] + ")"
                            finding = (
                                "{}.{}.{}\n"
                                "Parameters: {}\n"
                                "Description: {}\n"
                            ).format(
                                method,
                                function,
                                methodName,
                                results if self.debug_mode else normal_results,
                                functions[function]["Description"],
                            )
                else:
                    finding = (
                        "{}.{}.{}\n"
                        "Description: {}\n"
                        ).format(
                        method,
                        function,
                        methodName,
                        functions[function]["Description"],
                    )
                return finding

    def search_in_smali_files(self, search_query) -> str:
        for root, dirs, files in os.walk(self.output_dir):
            for file in files:
                if file.endswith(".smali"):
                    file_path = os.path.join(root, file)
                    with open(file_path, "r", encoding="utf-8") as file:
                        if search_query in file.read():
                            return file_path

    def parse_smali_for_method(self, search_invoke):
        smali_file_path = self.search_in_smali_files(search_invoke)
        if smali_file_path:
            assignment_match_regex = (
                r"(const/\d+|const-string|new-instance|move-result-object)"
                r" (\w+), \"?([^\"\s]+)\"?"
            )
            with open(smali_file_path, "r", encoding="utf-8") as file:
                lines = file.readlines()

            results = {"assignments": defaultdict(list),
                       "invoke_details": None}
            invoke_index = None

            for i, line in enumerate(lines):
                if search_invoke in line:
                    invoke_index = i
                    break

            if invoke_index is not None:
                method_start = None
                for i in range(invoke_index, -1, -1):
                    if lines[i].strip().startswith(".method"):
                        method_start = i
                        break

                if method_start is not None:
                    for line in lines[method_start:invoke_index]:
                        line_strip = line.strip()
                        assignment_match = re.match(
                            assignment_match_regex,
                            line_strip,
                        )
                        if assignment_match:
                            opcode, register, value = assignment_match.groups()
                            results["assignments"][register].append(
                                value.strip('"')
                            )

                    invoke_line = lines[invoke_index].strip()
                    invoke_match = re.match(r"invoke-\w+ {(.+?)}, (.+)",
                                            invoke_line)
                    if invoke_match:
                        registers, invoke_signature = invoke_match.groups()
                        register_values = {}
                        for reg in registers.split(", "):
                            reg = reg.strip()
                            if reg in results["assignments"]:
                                last_value = results["assignments"][reg][-1]
                                register_values[reg] = last_value
                            else:
                                register_values[reg] = "Unknown"
                        results["invoke_details"] = {
                            "signature": invoke_signature,
                            "registers": register_values,
                        }

            return results

    def decompile_apk(self) -> bool:
        self.output_dir = self.output_dir / self.calculate_name(
            open(self.apk_path, "rb").read()
        )
        command = [
            "./dex-tools/d2j-dex2smali.sh",
            self.apk_path,
            "--force",
            "-o",
            self.output_dir,
        ]
        try:
            subprocess.run(
                command, check=True, stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT
            )
            print(f"[+] Decompile successfully.. Path: {self.output_dir}")
            return True
        except subprocess.CalledProcessError:
            return False

    def calculate_name(self, file_data) -> str:
        m = hashlib.md5(file_data).hexdigest()
        self.hashName = f"decompile-{m[:8]}"
        return f"decompile-{m[:8]}"

    def parse_method_representation(self, method_repr: str) -> str:
        try:
            method_part = method_repr.split(" ")[-1]
            method_name = method_part.split("->")[1].split("(")[0]
            params_raw = method_part.split("(")[1].split(")")[0]
            return method_name, params_raw
        except (IndexError, ValueError):
            return "", ""

    def printMethods(self):
        for i in self.dx.find_methods():
            print(i)

    def printStrings(self):
        for i in self.dx.find_strings():
            print(i)

    def printClasses(self):
        for i in self.dx.find_classes():
            print(i)

    def config_analyze(self):
        try:
            with open(self.config_file_path, "r") as file:
                print("[+] Initialize config file..")
                self.config = json.load(file)
                self.permissionList = self.config["permissionList"]
                self.method_signatures = self.config["method_signatures"]
        except FileNotFoundError or FileExistsError:
            print(f"'{self.config_file_path}' file not found.")
            sys.exit(0)
        except json.JSONDecodeError:
            print(f"'{self.config_file_path}' wrong JSON format.")
            sys.exit(0)

        print(f"[*] Loaded Permission rule: {len(self.permissionList)}")
        print(f"[*] Loaded Method signatures: {len(self.method_signatures)}")
        methodsCount = 0
        for method in self.method_signatures:
            methodsCount += len(self.method_signatures[method]["functions"])
        print(f"[*] Loaded Methods: {methodsCount}")

    def analyzeResults(self):
        for analyze in self.permFindings:
            print("[+] Permission:", analyze)
        for analyze in self.findings:
            print("[+] Found:", analyze)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Static apk analysis tool for malware analysis')
    parser.add_argument('filePath', type=str, help='Apk/Dex path')
    parser.add_argument('--configPath', type=str, default="./config.json",
                        help='Config file path')
    parser.add_argument('--outputPath', type=str, default="./Analyzer",
                        help='Output file dir')
    parser.add_argument('--debugMode', type=bool, default=False,
                        help='Enable debug mode')
    args = parser.parse_args()

    res = Analyzer(apkPath=args.filePath,
                   config_file_path=args.configPath,
                   output_dir=args.outputPath,
                   debug_mode=args.debugMode)
    res.analyze()
    res.analyzeResults()
