#!/usr/bin/env python3
"""DNS protocol message encoder/decoder (RFC 1035)."""
import sys,struct,random

TYPES={'A':1,'AAAA':28,'CNAME':5,'MX':15,'NS':2,'TXT':16,'SOA':6,'PTR':12}
CLASSES={'IN':1}

def encode_name(name):
    result=b''
    for label in name.rstrip('.').split('.'):
        result+=bytes([len(label)])+label.encode()
    return result+b'\x00'

def decode_name(data,offset):
    labels=[];jumped=False;orig_offset=offset
    while True:
        length=data[offset]
        if length==0:offset+=1;break
        if length&0xC0==0xC0:  # pointer
            ptr=struct.unpack('>H',data[offset:offset+2])[0]&0x3FFF
            if not jumped:orig_offset=offset+2
            offset=ptr;jumped=True;continue
        offset+=1;labels.append(data[offset:offset+length].decode());offset+=length
    return'.'.join(labels),orig_offset if jumped else offset

def build_query(domain,qtype='A',qid=None):
    qid=qid or random.randint(0,65535)
    header=struct.pack('>HHHHHH',qid,0x0100,1,0,0,0)  # RD=1, 1 question
    question=encode_name(domain)+struct.pack('>HH',TYPES.get(qtype,1),1)
    return header+question

def parse_header(data):
    fields=struct.unpack('>HHHHHH',data[:12])
    return{'id':fields[0],'flags':fields[1],'qdcount':fields[2],
           'ancount':fields[3],'nscount':fields[4],'arcount':fields[5]}

def main():
    if len(sys.argv)>1 and sys.argv[1]=="--test":
        # Encode/decode name
        enc=encode_name("www.example.com")
        assert enc==b'\x03www\x07example\x03com\x00'
        name,_=decode_name(enc,0)
        assert name=="www.example.com"
        # Build query
        q=build_query("example.com","A",qid=0x1234)
        h=parse_header(q)
        assert h['id']==0x1234 and h['qdcount']==1
        assert len(q)==12+len(encode_name("example.com"))+4
        # Types
        assert TYPES['A']==1 and TYPES['AAAA']==28
        print("All tests passed!")
    else:
        q=build_query("example.com")
        print(f"DNS query: {q.hex()}")
        print(f"Length: {len(q)} bytes")
if __name__=="__main__":main()
