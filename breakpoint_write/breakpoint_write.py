# coding=utf-8
# @time     : 2019/7/23 10:42
# @author   : Wizdzz
import copy
import json
import sys
import logging
import traceback
import lldb

# LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
# logging.basicConfig(filename='LldbScriptTest.log', level=logging.DEBUG, format=LOG_FORMAT)


def breakpoint_write(debugger: lldb.SBDebugger, command: str, result, internal_dict):
    bpFilePathName = command
    if bpFilePathName is None or bpFilePathName == '':
        print('Error: need argument to determine the breakpoint file.')
        return
    elif bpFilePathName.count('"') > 0:
        bpFilePathName = bpFilePathName.replace('"', '')

    # serialize the breakpoint first
    res: lldb.SBCommandReturnObject = lldb.SBCommandReturnObject()
    cmd = 'breakpoint write -f %s' % ('"' + bpFilePathName + '"')
    lldb.debugger.GetCommandInterpreter().HandleCommand(cmd, res)  # breakpoint write failed, return
    if not res.Succeeded():
        print(res.GetError())
        return

    # then get the extra data for fix
    target: lldb.SBTarget = debugger.GetSelectedTarget()

    bpFixDataList = []
    bpFixData = {}
    for m in target.breakpoint_iter():
        brkLoct: lldb.SBBreakpointLocation = m.location[0]
        if brkLoct is None:
            bpFixDataList.append(None)
            continue

        sbAddr: lldb.SBAddress = brkLoct.GetAddress()
        bpFixData['offset'] = sbAddr.offset + sbAddr.GetSection().GetFileOffset()
        sbModule: lldb.SBModule = sbAddr.GetModule()
        bpFixData['moudleName'] = sbModule.GetFileSpec().GetFilename()

        # print("offset: %s, module: %s" % (bpFixData['offset'], sbModule.GetFileSpec().GetFilename()))

        bpFixDataList.append(copy.deepcopy(bpFixData))

    if len(bpFixDataList) == 0:
        print('Breakpoint list is empty, nothing to save.')
        return

    fixBpFile(bpFixDataList, bpFilePathName)


def fixBpFile(bpExtraDataList, bpFilePathName):
    try:
        with open(bpFilePathName, 'r') as f:
            fileContext = f.read()
            if fileContext == '':
                return
            bpData = json.loads(fileContext)

            for i in range(0, len(bpData)):
                bpResolver = bpData[i]['Breakpoint']['BKPTResolver']
                if (bpResolver is not None) and (bpResolver['Type'] == 'Address'):
                    bpResolver['Options']['AddressOffset'] = bpExtraDataList[i]['offset']
                    bpResolver['Options']['ModuleName'] = bpExtraDataList[i]['moudleName']
                else:
                    continue

        with open(bpFilePathName, 'w') as f:
            f.write(json.dumps(bpData))

        print("Succeed: breakpoint file save to %s." % bpFilePathName)
    except BaseException as e:
        s = traceback.format_exc()
        print(s)
        logging.error(s)


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f breakpoint_write.breakpoint_write bpw')
    print('The "bpw" python command has been installed and is ready for use.')


def main():
    try:
        print("main")
    except BaseException as e:
        s = traceback.format_exc()
        print(s)
        logging.error(s)


if __name__ == "__main__":
    sys.exit(main())
