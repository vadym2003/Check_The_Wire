from scapy.all import *
from pcapng import FileScanner
from pcapng import blocks
import io
import codecs
import dpkt
from itertools import repeat
import datetime
import time


def analyze_block(data_block, data_string):
    if ("GET" in data_string) or ("OK" in data_string) or ('302' in data_string):
        data = data_block[6]
        r=0
        if "GET" in data_block[7]:
            data.join(data_block[7])
            r=1
        """if ("GET" in data_string) and (r==0):
            print()
            print(data_block[7])
        elif("GET" in data_string) and (r==1):
            print()
            print(data_block[8])
        elif  ("OK" in data_string) or ('302' in data_string):
            print()
            print("Response ") """          
        packet_data = data.split('=')
        if(len(packet_data)>=3):
            request = packet_data[1]+" ".join(packet_data[2:])
        else:
            request = packet_data[1]
        request_ch = request.replace('\\x',' ')
        request_ch = request_ch.replace('[','')
        request_ch = request_ch.replace(':','')
        request_ch = request_ch.replace('@','')
        request_ch = request_ch.replace(';','')
        request_ch = request_ch.replace('<','')
        request_ch = request_ch.replace('~','')
        request_ch = request_ch.replace('|','')
        request_ch = request_ch.replace('(','')
        request_ch = request_ch.replace('\\n','')
        request_ch = request_ch.replace('\\t','')
        request_ch = request_ch.replace('&','')
        request_ch = request_ch.replace('\\\\','')
        request_ch = request_ch.replace('\#','')
        request_ch = request_ch.replace('\\r','')
        request_ch = request_ch.replace(')','')
        request_ch = request_ch.replace('>','')
        request_ch = request_ch.replace(']','')
        request_ch = request_ch.replace('$','')
        request_ch = request_ch.replace('!','')
        request_ch = request_ch.replace('\\','')
        request_ch = request_ch.replace('\`','')
        request_ch = request_ch.replace('%','')
        request_ch = request_ch.replace('}','')
        request_ch = request_ch.replace('{','')
        request_ch = request_ch.replace('HTTP/1.1',' OK')
        request_ch = request_ch.replace('GET',' GET')
        request_ch = request_ch.replace('?','')
        request_ch = request_ch.replace(',','')
        request_ch = request_ch.replace('\"','')
        request_ch = request_ch.replace('\'',' ')
        request_ch = request_ch.replace('_','')
        request_ch = request_ch.replace('/L','')
        request_ch = request_ch.replace('/','')
        request_ch = request_ch.replace('`','')  
        request_ch = request_ch.replace('/P','') 
        request_ch = request_ch.replace('.','')     
        
        
        
        if("GET" in data_string):
            return " " + str(request_ch)
            #print(get_request[n])
        elif("OK" in data_string) or ("302" in data_string):
            
            changebl = str(request_ch).split('00P')
            #print(changebl)
            if len(changebl)>2:
                middle = changebl[2].split(' ')
            elif len(changebl)==2:
                middle = changebl[1].split(' ')
            #print(middle)
            #print(str(middle[2]))
            result = str(middle[2]) + "." + middle[3] + "." + middle[4]
            #print(result)
            return " " + result
            #print(str(throw_response[n]))# + " Raw:" + str(request_ch))

def main(): 

    request_list = [str(" .test. ")]
    response_list = [str(" .test. ")]     
    
    print("\033[1;31;40mWrite path to pcap file here: \033[1;37;40m")
    path = str(input())
    
    fr = rdpcap(open(path, 'rb'))
    print(fr)
    
    FileExt = path.split('.')

    if FileExt[1] == "pcapng":    
        with open(path,"rb") as fp:    
            scanner = FileScanner(fp)
            
            for block in scanner:
                data_string = str(block)
                data_block = data_string.split(' ')
                if("HTTP" in data_string):
                    
                    if("GET" in data_string):
                        request_list.append(str(data_string + analyze_block(data_block,data_string)))
                        #print(get_request[n])
                    elif("OK" in data_string) or ("302" in data_string):
                        response_list.append(str(data_string + analyze_block(data_block,data_string)))
                        #print(throw_response[n])
            fp.close()
        #print(response_list)     
        
        t=1
        i=1
        while t < len(response_list):
            k=0
            #print(response_list[t])
            
            result = (response_list[t].split(' ')).pop() 
            measure = result.split('.')
            matching = list()
            #print(result)
            
            while i < len(request_list):
                
                
                if(measure[0] in str(request_list[i])):
                    matching.append(str(request_list[i]))
                    #print('Request: \n'+str(request_list[i]))
                    #print('Response \n'+str(response_list[t])) 
                                 
                
                i+=1
            i=1
            
            if(len(matching)>1):
                matching.clear()
                
                while i < len(request_list):
                    
                    if(str(measure[0]+" "+measure[1]) in str(request_list[i])):
                        matching.append(str(request_list[i]))
                        
                    i+=1                
                
            i=1
            if(len(matching)>1):
                matching.clear()
                
                while i < len(request_list):
                    
                    if(str(measure[0]+" "+measure[1]+" "+measure[2]) in str(request_list[i])):
                        matching.append(str(request_list[i]))
                        
                    i+=1                   
                
            print("Request: \n"+str(matching)) 
            try:
                match = str(matching.pop())
            except Exception:
                print("\033[1;33;40mNO Request\033[1;37;40m")
                k=1
            if(k==0):
                match_block = match.split(' ')
                request_time1 = str(match_block[2]).split("=")
                request_time2 = str(match_block[3]).split("=")
                request_time = (int(request_time1[1]) << 32) + int(request_time2[1])
                #print(request_time/1000000000.0)
                request_local_time = datetime.datetime.fromtimestamp(request_time/1000000000.0)
                #print(request_local_time)
            else:
                print("Request Not Found - Time Will Not Be Calculated")
            print("Response: \n"+response_list[t])
            
            if(k==0):
                match_block = response_list[t].split(' ')
                response_time1 = str(match_block[2]).split("=")
                response_time2 = str(match_block[3]).split("=")
                response_time = (int(response_time1[1]) << 32) + int(response_time2[1])
                #print(response_time/1000000000.0)
                response_local_time = datetime.datetime.fromtimestamp(response_time/1000000000.0)
                #print(response_local_time)
                print("\033[1;31;40mWaiting time = "+str(response_local_time-request_local_time)+"\033[1;37;40m")
            else:
                print("\033[1;33;40mRequest Not Found - Time Will Not Be Calculated\033[1;37;40m")            
            
            i=1
            t+=1
            
                
main()
