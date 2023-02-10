# -*- coding: utf-8 -*-

from fastapi import Request, FastAPI
import json
import paramiko



app = FastAPI(
    title="DPcheck",
    description="This is a POC for windows CVE search engindefault password checker",
    version="1.0",
)


#(mac, ip, vendor, model, function)
#Post example
#[
#	{
#		"mac": "11:22:33:44:55",
#		"ip": "192.168.1.1",
#		"vendor": "test",
#		"model": "t1234",
#		"function": "router"
#	}
#]
#


@app.post("/checkDP")
async def checkDP(request: Request):
    jsonInput = await request.json()
    resp = main(jsonInput)
    return resp

#Post example
#["11:22:33:44:55","66:77:88:99:00"]
#
@app.post("/getDP")
async def getDP(request: Request):
    jsonInput = await request.json()
    assetList = readDB(jsonInput)
    return assetList


def main( jsonInput):
    macList=[]
    if isinstance(jsonInput, list):
        for asset in jsonInput:
            if isinstance(asset, dict):
                macList.append(asset["mac"])
                checkAssetDP(asset)
    
    return readDB(macList)  



def checkAssetDP(asset):
    vendor =asset["vendor"]
    model = asset["model"]
    assetDP={}
    assetDPgeneric={}
    
    
    if vendor in DPdict.keys():
        for entry in DPdict[vendor]:
            if entry["Model/Software name"] == "":
                assetDPgeneric= entry
            if model == entry["Model/Software name"]:
                assetDP= entry
                break
        if not assetDP:
            if assetDPgeneric:
                assetDP = assetDPgeneric
            else:
                assetDP = DPdict[vendor][0]
        
        if not assetDP:
            return "error"
        
        return testDP(asset, assetDP)        
                                
            
    else:
        return None
def testDP(asset, assetDP):
    accessType = assetDP["Access Type"]
    if "Telnet" in accessType:
        testDPTelnet(asset, assetDP)
    if "SSH" in accessType:
        testDPSSH(asset, assetDP)
    if "HTTP" in accessType:
        testDPHTTP(asset, assetDP)
    if "SNMP" in accessType:
        testDPSNMP(asset, assetDP)
    if "Any" in accessType or "Multi" in accessType or accessType =="" :
        testDPall(asset, assetDP)
        
def testDPTelnet(asset, assetDP):
    #todo
    return

def testDPSNMP(asset, assetDP):
    #todo
    return

# Check default password via SSH 
def testDPSSH(asset, assetDP): 
    
    host = asset["ip"]
    username = assetDP["Username"]
    password = assetDP["Password"]
    
    try:        
        client = paramiko.client.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=username, password=password)
    except paramiko.AuthenticationException as error:
        if "authentication" in str(error).lower():
            return False
        else:
            return None
    else:
        client.close()
        saveDB(asset,assetDP,"SSH")
        return True
    
    return None

def testDPHTTP(asset, assetDP):
    #todo
    return

def testDPall(asset, assetDP):
    testDPTelnet(asset, assetDP)
    testDPSNMP(asset, assetDP)
    testDPSSH(asset, assetDP)
    testDPHTTP(asset, assetDP)    
    #todo
    return

def saveDB(asset,assetDP,protocol):
    db ={}
    with open('assetDB.json', "r") as f:
        db = json.load(f)
        if asset["mac"] not in db.keys():
            db[asset["mac"]] = asset
            
        db[asset["mac"]][protocol] = {"Username": assetDP["Username"] , "Password": assetDP["Password"]}
    with open('assetDB.json', "w") as f:    
        json.dump(db, f)
    return
       
def readDB(macList):
    assetList=[]
    with open('assetDB.json', "r") as f:
        db = json.load(f)
        if db and isinstance(db, dict):
            for mac in macList:
                if mac in list(db.keys()):
                    assetList.append(db[mac])
    return assetList
    
    
def loadDP():        
    f = open('vendorDict.json')
    data = json.load(f)
    f.close()
    return data


DPdict = loadDP()