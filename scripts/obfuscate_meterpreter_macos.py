#!/usr/bin/python3

import sys
import tempfile
import argparse
import os
import logging
import re
import traceback
import subprocess
import shutil
import platform

from collections import Counter
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from tqdm import tqdm
from typing import List
from chardet import detect

# todo
# Auto include folders
# Only a specific subfolder
# config init
# stackprinter.set_excepthook(style='darkbg2') # stacktraces with variables' values
logging.basicConfig(level=logging.INFO)

AVCLEANER_PATH = "/Users/vladimir/dev/scrt/avcleaner/cmake-build-debug/avcleaner.bin"
PATCH_SYSCALL_PATH = "/Users/vladimir/dev/metasploit-evasion/build/patch_enum_syscalls.c"
WIN_INCLUDE = "/Users/vladimir/dev/anti-av/hkclnr/avcleaner"
CLANG_PATH = "/usr/local/Cellar/llvm/9.0.1"#"/usr/lib/clang/8.0.1/"
# to reduce processing time / likelihook of critical failures.
FILES_BLACKLIST = [
                "python",
                "jpeg-8",
                "ext_server_mimikatz",
                "sqlite",
                "mimidrv",
                "LoadLibraryR",
                "zlib",
                "DelayLoadMetSrv",
                "pageantjacker",
                "RC4Encrypt",
                "webcam.cpp",
                "libpeinfect",
                "libpetool"
                ]
LOGFILE = "output_result.log"
g_arguments = {}


"""
    Lists all C/C++ source files in a given folder
"""
def get_translation_units(root_dir, whitelist=[]) -> List:

    tunits: List = []

    for (dirpath, dirs, files) in os.walk(root_dir):

        for filename in files:

            filename = os.path.join(dirpath, filename)

            if len(whitelist) > 0 and any(x in os.path.abspath(filename) for x in whitelist):

                if os.path.splitext(filename)[1] in [".cpp", ".c"]:
                    tunits += [filename]

            elif len(whitelist) == 0:
                if os.path.splitext(filename)[1] in [".cpp", ".c"]:
                    tunits += [filename]

        for folder in dirs:

            tunits += get_translation_units(folder, whitelist)

    return tunits


def is_interesting(string):

    for x in ["include", "dprintf", "#else", "#pragma", "#if", "#elif", "extern \"C\""]:
        if x in string:
            return False

    return True

def exec(command):
    p = subprocess.Popen(command, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, shell=True)
    rout = ""
    iterations = 0

    while(True):

        retcode = p.poll()  # returns None while subprocess is running
        out_raw = p.stdout.readline()
        out = out_raw.decode('utf-8', "ignore")

        iterations += 1
        rout += out
        if(retcode is not None):
            break
    return rout


def run_avcleaner(filepath, g_arguments):

    flags = ""

    if g_arguments.strings:
        flags += "-strings=true"
    if g_arguments.debug:
        flags += " -debug=true"
    #if g_arguments.edit:
    flags += " -edit=true"
    if g_arguments.api:
        flags += " -api=true"

    file_content = ""
    encoding = get_encoding_type(filepath)
    with open(filepath, "r", encoding=encoding) as f:
        file_content = f.read()

    # slow
    #if file_content.count("../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c\"") > 0:

        #flags += " -skip-definitions"
        #logging.warning("Skipping copy of patch_syscall.txt")

    include_basepath = ""
    if g_arguments.path:
        include_basepath = g_arguments.path
    else:
        include_basepath = os.path.dirname(g_arguments.file)

    command = f"""{AVCLEANER_PATH} {flags} {filepath} -- -w -D "_WIN64" -D "_UNICODE" -D "UNICODE" -D "_WINSOCK_DEPRECATED_NO_WARNINGS" -target x86_64-pc-windows-msvc19.15.26726\
    "-fsyntax-only" "-disable-free" "-disable-llvm-verifier" "-discard-value-names"\
    "-dwarf-column-info" "-debugger-tuning=gdb" "-momit-leaf-frame-pointer" "-v"\
    "-I" {WIN_INCLUDE}/Include/10.0.17134.0/um \
    "-I" {WIN_INCLUDE}/Include/msvc-14.15.26726-include\
    "-I" {WIN_INCLUDE}/Include/10.0.17134.0/ucrt \
    "-I" {WIN_INCLUDE}/Include/10.0.17134.0/shared \
    "-I" {WIN_INCLUDE}/Include/10.0.17134.0/winrt \
    -I "{include_basepath}"/extensions/kiwi/mimikatz/inc/ \
    "-I" {CLANG_PATH}/include \
    "-I" {CLANG_PATH} \
    -I /usr/x86_64-w64-mingw32/include \
    -I /usr/include/\
    -I "{include_basepath}"/..\
    -I "{include_basepath}"\
    -I "{include_basepath}"/ReflectiveDLLInjection/inject/src/ \
    -I "{include_basepath}"/common \
    -I "{include_basepath}"/server \
    -I "{include_basepath}"/extensions/stdapi/server/ \
    -I "{include_basepath}"/ReflectiveDLLInjection/common/ \
    -I"/usr/x86_64-w64-mingw32/include/"\
    "-w" \
    -ferror-limit=1900\
    -fmessage-length=237\
    "-fno-use-cxa-atexit" "-fms-extensions" "-fms-compatibility" \
    "-fms-compatibility-version=19.15.26726" "-std=c++14" "-fdelayed-template-parsing" "-fobjc-runtime=gcc" "-fcxx-exceptions" "-fexceptions" "-fdiagnostics-show-option" "-fcolor-diagnostics" "-x" "c++"
    """


    res = exec(command)
    logging.info(res)
    return res


def scan_for_strings(file):

    # Warning: python regex are very slow
    if platform.system == "Windows":

        regex = re.compile("\"([^\\\"]+|\\.)*?\"")
        # only_code = filter(lambda x: "#include" not in x, file_content)
        is_matched = False

        file_content = []
        with open(file, "r") as f:
            file_content = f.readlines()  # will probably break because of non-utf-8 files

        for line in file_content:

            if not is_interesting(line):
                continue

            matches = re.finditer(regex, line)

            for _, match in enumerate(matches, start=1):

                tqdm.write(match.group())
                is_matched = True

        # return re.match(regex, "\n".join(only_code))
        return is_matched

    command = f"egrep '\"([^\\\"]+|\\.)*?\"' {file}"  # yolo but very fast

    rout = exec(command)
    matches = list(filter(lambda x: is_interesting(x), rout.split("\n")))
    return len(matches) > 0


def scan_for_bad_apis(file, pbar):

    bad_api = [
        "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
        "CreateRemoteThreadEx", "NtAllocateVirtualMemory",
        "NtAlpcConnectPort", "NtAlpcConnectPortEx",
        "NtAlpcSendWaitReceivePort", "NtConnectPort", "NtCreateProcess",
        "NtCreateProcessEx", "NtCreateSection", "NtCreateThread",
        "NtCreateThreadEx", "NtCreateUserProcess", "NtFreeVirtualMemory",
        "NtMapViewOfSection", "NtProtectVirtualMemory", "NtQueueApcThread",
        "NtQueueApcThreadEx", "NtReadVirtualMemory", "NtRequestWaitReplyPort",
        "NtResumeProcess", "NtResumeThread", "NtSecureConnectPort",
        "NtSetContextThread", "NtSetInformationProcess",
        "NtSetInformationThread", "NtSuspendProcess", "NtSuspendThread",
        "NtUnmapViewOfSection", "NtWriteVirtualMemory",
        "ZwAllocateVirtualMemory", "ZwAlpcConnectPort",
        "ZwAlpcConnectPortEx", "ZwAlpcSendWaitReceivePort", "ZwConnectPort",
        "ZwCreateProcess", "ZwCreateProcessEx", "ZwCreateSection",
        "ZwCreateThread", "ZwCreateThreadEx", "ZwCreateUserProcess",
        "ZwFreeVirtualMemory", "ZwMapViewOfSection", "ZwProtectVirtualMemory",
        "ZwQueueApcThread", "ZwQueueApcThreadEx", "ZwReadVirtualMemory",
        "ZwRequestWaitReplyPort", "ZwResumeProcess", "ZwResumeThread",
        "ZwSecureConnectPort", "ZwSetContextThread", "ZwSetInformationProcess",
        "ZwSetInformationThread", "ZwSuspendProcess", "ZwSuspendThread",
        "ZwUnmapViewOfSection", "ZwWriteVirtualMemory", "SamEnumerateDomainsInSamServer",
        "SamRidToSid", "GetTempFileNameA", "SamConnect", "SamConnectWithCreds", "SamEnumerateDomainsInSamServer",
        "SamLookupDomainInSamServer", "SamOpenDomain", "SamOpenUser", "SamOpenGroup", "SamOpenAlias",
        "SamQueryInformationUser", "SamSetInformationUser", "SamiChangePasswordUser", "SamGetGroupsForUser",
        "SamGetAliasMembership", "SamGetMembersInGroup", "SamGetMembersInAlias", "SamEnumerateUsersInDomain",
        "SamEnumerateGroupsInDomain", "SamEnumerateAliasesInDomain", "SamLookupNamesInDomain",
        "SamLookupIdsInDomain", "SamRidToSid", "SamCloseHandle", "SamFreeMemory"
    ]

    # only_code = filter(lambda x: "#include" not in x, file_content)
    is_matched = False

    file_content = ""
    api_occurrences = Counter()

    encoding = get_encoding_type(file)
    with open(file, "r", encoding=encoding) as f:
        file_content = f.read()

    for api in bad_api:

        tomatch_str = f"\"{api}\"" # string occurrence, probably GetProcAddress
        tomatch_call = f"{api}(" # API call

        occurrences = file_content.count(tomatch_str)
        occurrences += file_content.count(tomatch_call)
        api_occurrences[api] += occurrences
        is_matched |= occurrences > 0

    only_useful = Counter(el for el in api_occurrences.elements() if api_occurrences[el] > 0)

    if len(list(only_useful.elements())) > 0:
        pbar.write(file + " -> " + str(only_useful))

    return is_matched, only_useful

def is_blacklisted(filepath):

    for b in FILES_BLACKLIST:

        if b in filepath:
            return True
    return False

# get file encoding type, to be used when opening non-utf-8 files.
def get_encoding_type(file):

    with open(file, 'rb') as f:
        rawdata = f.read()

    return detect(rawdata)['encoding']

def analyze_files(tunits):

    files_with_strings = []
    files_with_bad_apis = []
    api_occurrences = Counter()

    logging.info(f"Analyzing {len(tunits)} files...")
    pbar = tqdm(tunits)

    for file in pbar:

        pbar.set_description_str(desc=file, refresh=True)

        if is_blacklisted(file):
            continue

        if not os.path.exists(file):
            logging.warning(f"File {file} does not exist")
            continue

        if scan_for_strings(file):
            files_with_strings += [re.sub(g_arguments.path, "", file)]

        is_matched, tmp_counter = scan_for_bad_apis(file, pbar)

        if is_matched:
            api_occurrences += tmp_counter
            files_with_bad_apis += [re.sub(g_arguments.path, "", file)]

    logging.info(f"Found {len(files_with_strings)} files with strings.")
    logging.info(f"Found {len(files_with_bad_apis)} files with suspicious API calls.")

    pbar.refresh()
    pbar.clear()
    pbar.close()
    return files_with_strings, files_with_bad_apis, api_occurrences

def display_stats(occurrences_before, occurrences_after):

    for k,v in occurrences_before.items():

        total = v
        total_after = occurrences_after[k]
        replaced = total - total_after

        logging.info(f"{replaced}/{total} occurrences of {k} replaced.")


def obfuscate_meterpreter(arguments):

    meterpreter_path = arguments.path

    if not os.path.exists(meterpreter_path) or not os.path.isdir(meterpreter_path):
        logging.error("Path provided is invalid")
        sys.exit(-1)

    whitelist = []
    if arguments.only_match and len(arguments.only_match) > 0:
        whitelist = arguments.only_match.split(",")
    tunits = get_translation_units(meterpreter_path, whitelist)

    files_with_strings, files_with_bad_apis, api_occurrences = analyze_files(tunits)

    #return # TODO remove
    # now that the files to be processed are collected, we can dispatch them
    # in thread pools and launch the preprocessing tool on them.
    actual_folder = arguments.path
    logging.info(f"Using {actual_folder} as base path")
    if not arguments.edit:
        logging.warning("no edit argument")
        tempfolder = tempfile.mkdtemp()
        #shutil.rmtree(tempfolder)  # yolo
        actual_folder = os.path.join(tempfolder, os.path.basename(arguments.path))

        logging.info(f"Writing result to {actual_folder}")
        shutil.copytree(arguments.path, actual_folder)

    total_output = ""

    all_files = list(set(files_with_strings + files_with_bad_apis))
    print(all_files)
    tmp_files = []
    for file in all_files:


        if file[0] == os.sep:
            file = file[1:]

        if not os.path.exists(os.path.join(actual_folder, file)):
            logging.info(f"Using {actual_folder} as base path")

            logging.warning(f"File does not exist: {os.path.join(actual_folder, file)}")
            continue

        tmp_files += [os.path.join(actual_folder, file)]

    with ProcessPoolExecutor(max_workers=16) as executor:
        results = list(tqdm(executor.map(run_avcleaner, tmp_files, [g_arguments]*len(tmp_files))))

    logging.info("Done")
    tunits = get_translation_units(actual_folder, whitelist)
    _, _, new_api_occurrences = analyze_files(tunits)

    display_stats(api_occurrences, new_api_occurrences)

    output_log_path = os.path.join(actual_folder, LOGFILE)
    logging.info(f"Writing output log file to {output_log_path}")

    with open(output_log_path, "w") as f:

        sep = "\n"+'-'*80
        f.write(sep.join(results))


def obfuscate_single(filepath):

    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        logging.error("Path provided is invalid")
        sys.exit(-1)


    tempfolder = tempfile.mkdtemp()

    logging.info(f"Creating temporary folder @ {tempfolder}")

    # backup the file
    tempfile_path = shutil.copy(filepath, tempfolder)

    logging.info(f"File @ {tempfile_path}")
    results = run_avcleaner(tempfile_path)

    logging.info("Done")
    output_log_path = os.path.join(tempfolder, LOGFILE)
    logging.info(f"Output log file @ {output_log_path}")

    with open(output_log_path, "w") as f:

        sep = "\n"+'-'*80
        f.write(results)


if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-p', '--path',
                       help="set path to meterpreter's codebase")

    group.add_argument('-f', '--file', help="set path to a single file")

    parser.add_argument('-d', '--debug', action='store_true',
                        help="enable function tracing with dprintf calls.")

    parser.add_argument('-e', '--edit', action='store_true',
                        help="enable in place patch of the source files.")

    parser.add_argument('-a', '--api', action='store_true',
                        help="enable api calls obfuscation.")

    parser.add_argument('-s', '--strings', action='store_true',
                        help="enable string literals obfuscation.")

    parser.add_argument("-o", '--only-match', help="only obfuscate files whose absolute path contains the provided value (i.e -o metsrv,kiwi will match /toto/tata/metsrv/* or /toto/tata/kiwi/*)")
    args = parser.parse_args()
    g_arguments = args  # hmmmm

    if args.file:
        obfuscate_single(args.file)
    else:
        shutil.copyfile(PATCH_SYSCALL_PATH, "/tmp/patch_enum_syscalls.txt") # avcleaner's cwd is above 'source'
        obfuscate_meterpreter(args)
