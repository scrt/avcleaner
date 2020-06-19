import sys

# for i in `grep "ClInclude Include=" mimikatz.vcxproj | rg "\"(.*)\" />" -r '$1' -o | tr '\\' '/'` ; do greadlink -f $i ; done | paste -s -d' ' - > /tmp/includes.txt


if __name__ == '__main__':

    if len(sys.argv) < 2:
        print("files must all be absolute paths")
        print("Usage: script.py file1 file2 file3")
        exit(-1)

    files = sys.argv[1:]


    folders = set()

    for file in files:

        dirs = file.split("/")[1:-1] # split on /, eliminate the last item because it is a file

        basepath = ""
        for d in dirs:
            basepath += "/" + d
            folders.add(basepath)

    folders_sorted = sorted(list(folders))
    [print(x) for x in folders_sorted]