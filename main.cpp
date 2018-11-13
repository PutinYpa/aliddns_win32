//---------------------------------------------------------------------------

#include <vcl.h>
#pragma hdrstop

#include "main.h"
#include "stdio.h"
//#include <winsock2.h>
#include "IniFiles.hpp"
#include <time.h>

//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma link "trayicon"
#pragma resource "*.dfm"
TForm1 *Form1;
//---------------------------------------------------------------------------
#define SHA1_LITTLE_ENDIAN  
  
#define _R0(v,w,x,y,z,i) { z+=((w&(x^y))^y)+SHABLK0(i)+0x5A827999+ROL32(v,5); w=ROL32(w,30); }  
#define _R1(v,w,x,y,z,i) { z+=((w&(x^y))^y)+SHABLK(i)+0x5A827999+ROL32(v,5); w=ROL32(w,30); }  
#define _R2(v,w,x,y,z,i) { z+=(w^x^y)+SHABLK(i)+0x6ED9EBA1+ROL32(v,5); w=ROL32(w,30); }
#define _R3(v,w,x,y,z,i) { z+=(((w|x)&y)|(w&x))+SHABLK(i)+0x8F1BBCDC+ROL32(v,5); w=ROL32(w,30); }  
#define _R4(v,w,x,y,z,i) { z+=(w^x^y)+SHABLK(i)+0xCA62C1D6+ROL32(v,5); w=ROL32(w,30); }  

#define SHABLK0(i) (m_block->l[i] = (ROL32(m_block->l[i],24) & 0xFF00FF00) | (ROL32(m_block->l[i],8) & 0x00FF00FF))

#define ROL32(_val32, _nBits) (((_val32)<<(_nBits))|((_val32)>>(32-(_nBits))))  
  
#define SHABLK(i) (m_block->l[i&15] = ROL32(m_block->l[(i+13)&15] ^ m_block->l[(i+8)&15] ^ m_block->l[(i+2)&15] ^ m_block->l[i&15],1))  
//==================================================================================================  
typedef union  
{  
  char  c[64];  
  unsigned long l[16];  
} SHA1_WORKSPACE_BLOCK;  
//==================================================================================================  
class CHMAC_SHA1
{  
  private:  
     unsigned long m_state[5];
     unsigned long m_count[2];  
     unsigned long __reserved1[1];  
     char  m_buffer[64];  
     char  m_digest[20];  
     unsigned long __reserved2[3];  
     unsigned char m_ipad[64];
     unsigned char  m_opad[64];
     char * szReport ;
     char * SHA1_Key ;
     char * AppendBuf1 ;
     char * AppendBuf2 ;
     char  m_workspace[64];
     SHA1_WORKSPACE_BLOCK *m_block; // SHA1 pointer to the byte array above

     void Reset();
     void Update(char *data, unsigned long len);
     void Transform(unsigned long *state, char *buffer);
     void Final();

     enum {
                SHA1_DIGEST_LENGTH  = 20,
                SHA1_BLOCK_SIZE     = 64,
                HMAC_BUF_LEN        = 4096
          } ;
  public:  
  
     CHMAC_SHA1()  
                :szReport(new char[HMAC_BUF_LEN]),  
                    AppendBuf1(new char[HMAC_BUF_LEN]),  
                    AppendBuf2(new char[HMAC_BUF_LEN]),  
                    SHA1_Key(new char[HMAC_BUF_LEN])  
                    {
                        m_block = (SHA1_WORKSPACE_BLOCK *)m_workspace;
                        Reset();
                    }
         ~CHMAC_SHA1()  
                    {
                        delete[] szReport ;
                        delete[] AppendBuf1 ;
                        delete[] AppendBuf2 ;
                        delete[] SHA1_Key ;
                        Reset();
                    }
                    
         void BinHMAC_SHA1(BYTE *text, int text_len, BYTE *key, int key_len, BYTE *sha1);//二进制编码  
         String HexHMAC_SHA1(BYTE *text, int text_len, BYTE *key, int key_len);//十六进制字符串  
         String Base64HMAC_SHA1(BYTE *text, int text_len, BYTE *key, int key_len);//Base64编码  
  
         String Base64Encode(char *s,int len);  
         String Base64Decode(String source);  
};  
//=====================================================================================  
void CHMAC_SHA1::Reset()  
{  
  m_state[0] = 0x67452301;  
  m_state[1] = 0xEFCDAB89;  
  m_state[2] = 0x98BADCFE;  
  m_state[3] = 0x10325476;  
  m_state[4] = 0xC3D2E1F0;  
  m_count[0] = 0;  
  m_count[1] = 0;  
}  
//---------------------------------------------------------------------------------------  
void CHMAC_SHA1::Update(char *data, unsigned long len)  
{  
 unsigned long i, j;  
 j=(m_count[0] >> 3) & 63;  
 if((m_count[0] += len << 3) < (len << 3)) m_count[1]++;  
    m_count[1] += (len >> 29);  
 if((j + len) > 63)  
    {  
     i = 64 - j;  
     memcpy(&m_buffer[j], data, i);  
     Transform(m_state, m_buffer);  
     for(; i + 63 < len; i += 64)  
        Transform(m_state, &data[i]);  
     j = 0;  
    }  
 else  
    i = 0;  
 memcpy(&m_buffer[j], &data[i], len - i);  
}  
//-------------------------------------------------------------------------------------  
void CHMAC_SHA1::Transform(unsigned long *state, char *buffer)  
{  
  unsigned long a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];  
  memcpy(m_block, buffer, 64);  
  _R0(a,b,c,d,e, 0); _R0(e,a,b,c,d, 1); _R0(d,e,a,b,c, 2); _R0(c,d,e,a,b, 3);  // 4 rounds of 20 operations each. Loop unrolled.  
  _R0(b,c,d,e,a, 4); _R0(a,b,c,d,e, 5); _R0(e,a,b,c,d, 6); _R0(d,e,a,b,c, 7);  
  _R0(c,d,e,a,b, 8); _R0(b,c,d,e,a, 9); _R0(a,b,c,d,e,10); _R0(e,a,b,c,d,11);  
  _R0(d,e,a,b,c,12); _R0(c,d,e,a,b,13); _R0(b,c,d,e,a,14); _R0(a,b,c,d,e,15);  
  _R1(e,a,b,c,d,16); _R1(d,e,a,b,c,17); _R1(c,d,e,a,b,18); _R1(b,c,d,e,a,19);  
  _R2(a,b,c,d,e,20); _R2(e,a,b,c,d,21); _R2(d,e,a,b,c,22); _R2(c,d,e,a,b,23);  
  _R2(b,c,d,e,a,24); _R2(a,b,c,d,e,25); _R2(e,a,b,c,d,26); _R2(d,e,a,b,c,27);  
  _R2(c,d,e,a,b,28); _R2(b,c,d,e,a,29); _R2(a,b,c,d,e,30); _R2(e,a,b,c,d,31);  
  _R2(d,e,a,b,c,32); _R2(c,d,e,a,b,33); _R2(b,c,d,e,a,34); _R2(a,b,c,d,e,35);  
  _R2(e,a,b,c,d,36); _R2(d,e,a,b,c,37); _R2(c,d,e,a,b,38); _R2(b,c,d,e,a,39);  
  _R3(a,b,c,d,e,40); _R3(e,a,b,c,d,41); _R3(d,e,a,b,c,42); _R3(c,d,e,a,b,43);  
  _R3(b,c,d,e,a,44); _R3(a,b,c,d,e,45); _R3(e,a,b,c,d,46); _R3(d,e,a,b,c,47);  
  _R3(c,d,e,a,b,48); _R3(b,c,d,e,a,49); _R3(a,b,c,d,e,50); _R3(e,a,b,c,d,51);  
  _R3(d,e,a,b,c,52); _R3(c,d,e,a,b,53); _R3(b,c,d,e,a,54); _R3(a,b,c,d,e,55);  
  _R3(e,a,b,c,d,56); _R3(d,e,a,b,c,57); _R3(c,d,e,a,b,58); _R3(b,c,d,e,a,59);  
  _R4(a,b,c,d,e,60); _R4(e,a,b,c,d,61); _R4(d,e,a,b,c,62); _R4(c,d,e,a,b,63);  
  _R4(b,c,d,e,a,64); _R4(a,b,c,d,e,65); _R4(e,a,b,c,d,66); _R4(d,e,a,b,c,67);  
  _R4(c,d,e,a,b,68); _R4(b,c,d,e,a,69); _R4(a,b,c,d,e,70); _R4(e,a,b,c,d,71);  
  _R4(d,e,a,b,c,72); _R4(c,d,e,a,b,73); _R4(b,c,d,e,a,74); _R4(a,b,c,d,e,75);  
  _R4(e,a,b,c,d,76); _R4(d,e,a,b,c,77); _R4(c,d,e,a,b,78); _R4(b,c,d,e,a,79);  
  
   state[0] += a;// Add the working vars back into state  
   state[1] += b;  
   state[2] += c;  
   state[3] += d;  
   state[4] += e;  
}  
//----------------------------------------------------------------------------------------------  
void CHMAC_SHA1::Final()  
{  
 unsigned long i;  
 char  finalcount[8];  
 for(i = 0; i < 8; i++)  
    finalcount[i] = (char)((m_count[((i >= 4) ? 0 : 1)]  >> ((3 - (i & 3)) * 8) ) & 255); // Endian independent  
 Update((char *)"\200", 1);  
 while ((m_count[0] & 504) != 448)  
      Update((char *)"\0", 1);  
 Update(finalcount, 8); // Cause a SHA1Transform()  
 for(i = 0; i < 20; i++)  
     m_digest[i] = (char )((m_state[i >> 2] >> ((3 - (i & 3)) * 8) ) & 255);  
}  
//------------------------------------------------------------------------------------------------  
void CHMAC_SHA1::BinHMAC_SHA1(BYTE *text, int text_len, BYTE *key, int key_len, BYTE *digest)  
{  
 memset(SHA1_Key, 0, SHA1_BLOCK_SIZE);  
 memset(m_ipad, 0x36, sizeof(m_ipad));  
 memset(m_opad, 0x5c, sizeof(m_opad));  
  
 if (key_len > SHA1_BLOCK_SIZE)/* STEP 1 */  
    {  
     Reset();  
     Update((char *)key, key_len);  
     Final();  
     memcpy(SHA1_Key, m_digest, 20);  
     }  
 else  
     memcpy(SHA1_Key, key, key_len);  
  
 for (int i=0; i<sizeof(m_ipad); i++)    /* STEP 2 */  
      m_ipad[i] ^= SHA1_Key[i];  
  
 memcpy(AppendBuf1, m_ipad, sizeof(m_ipad));/* STEP 3 */  
 memcpy(AppendBuf1 + sizeof(m_ipad), text, text_len);  
  
 Reset(); /* STEP 4 */  
 Update((char *)AppendBuf1, sizeof(m_ipad) + text_len);  
 Final();  
 memcpy(szReport, m_digest, 20);  
  
 for (int j=0; j<sizeof(m_opad); j++)/* STEP 5 */  
      m_opad[j] ^= SHA1_Key[j];  
  
 memcpy(AppendBuf2, m_opad, sizeof(m_opad));/* STEP 6 */  
 memcpy(AppendBuf2 + sizeof(m_opad), szReport, SHA1_DIGEST_LENGTH);  
  
 Reset();/*STEP 7 */  
 Update((char *)AppendBuf2, sizeof(m_opad) + SHA1_DIGEST_LENGTH);  
 Final();  
 memcpy(digest, m_digest, 20);  
}  
//-----------------------------------------------------------------------------------  
String CHMAC_SHA1::HexHMAC_SHA1(BYTE *text, int text_len, BYTE *key, int key_len)  
{  
  String sha1;  
  unsigned char binsha1[20];  
  BinHMAC_SHA1(text,text_len,key,key_len,binsha1);  
  for(int i=0;i<20;i++)  
     sha1+=IntToHex(binsha1[i],2);  
  return sha1;  
 }  
//-----------------------------------------------------------------------------------  
String CHMAC_SHA1::Base64HMAC_SHA1(BYTE *text, int text_len, BYTE *key, int key_len)  
{  
  String sha1;  
  String StrSha1;  
  unsigned char binsha1[20];
  BinHMAC_SHA1(text,text_len,key,key_len,binsha1);

  return Base64Encode(binsha1,20);

 }  
//==================================================================================  
String CHMAC_SHA1::Base64Encode(char *s,int len)
{  
  int m_len; //字符串长度  
  int i; //循环变量  
  int m_tmp; //临时变量  
  String m_64code; //储存Base64编码的字符串  
  unsigned char* m_s; //临时存储参数字符串　  
  
  char m_64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";//Base64字符表  
  m_len = len;//取得字符串长度  
  m_s = s;  
  m_64code="";//返回串置空  
  
  for(i=0;i<m_len-m_len%3;i+=3) //处理3的倍数以内的字符  
    {  
     m_tmp=m_s[i]/4;  
     m_64code+=m_64[m_tmp];  
     m_tmp=m_s[i]%4*16 + m_s[i+1]/16;  
     m_64code+=m_64[m_tmp];  
     m_tmp=m_s[i+1]%16*4 + m_s[i+2]/64;  
     m_64code+=m_64[m_tmp];  
     m_tmp=m_s[i+2]%64;  
     m_64code+=m_64[m_tmp];  
    }  
  
   if(m_len%3==2)//如果字符串的长度被3除余2 ,不足的位数补0，尾部补“=”  
    {  
     m_tmp=m_s[m_len-2]/4;  
     m_64code+=m_64[m_tmp];  
     m_tmp=m_s[m_len-2]%4*16+m_s[m_len-1]/16;  
     m_64code+=m_64[m_tmp];  
     m_tmp=m_s[m_len-1]%16*4;  
     m_64code+=m_64[m_tmp];  
     m_64code+='=';  
    }  
  
   if(m_len%3==1) //如果字符串的长度被3除余1 ，不足的位数补0，尾部补两个“=”  
    {  
     m_tmp=m_s[m_len-1]/4;  
     m_64code+=m_64[m_tmp];  
     m_tmp=m_s[m_len-1]%4*16;  
     m_64code+=m_64[m_tmp];  
     m_64code+="==";  
    }  
   return m_64code;  
 }

/////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////
String curl(String args)
{
      String ret;
      SECURITY_ATTRIBUTES sa          = {0};
      STARTUPINFO         si          = {0};
      PROCESS_INFORMATION pi          = {0};
      HANDLE              hPipeOutputRead  = NULL;
      HANDLE              hPipeOutputWrite = NULL;
      HANDLE              hPipeInputRead   = NULL;
      HANDLE              hPipeInputWrite  = NULL;
      BOOL                bTest = 0;
      DWORD               dwNumberOfBytesRead = 0;
      CHAR                szMsg[100];
      CHAR                szBuffer[256];

      sa.nLength = sizeof(sa);
      sa.bInheritHandle = TRUE;
      sa.lpSecurityDescriptor = NULL;


      // Create pipe for standard output redirection.
      CreatePipe(&hPipeOutputRead,  // read handle
              &hPipeOutputWrite, // write handle
              &sa,      // security attributes
              0      // number of bytes reserved for pipe - 0 default
              );
 
      // Create pipe for standard input redirection.
      CreatePipe(&hPipeInputRead,  // read handle
              &hPipeInputWrite, // write handle
              &sa,      // security attributes
              0      // number of bytes reserved for pipe - 0 default
              );
 
      // Make child process use hPipeOutputWrite as standard out,
      // and make sure it does not show on screen.
      si.cb = sizeof(si);
      si.dwFlags     = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
      si.wShowWindow = SW_HIDE;
      si.hStdInput   = hPipeInputRead;
      si.hStdOutput  = hPipeOutputWrite;
      si.hStdError   = hPipeOutputWrite;
 
      CreateProcess (
            NULL, ("curl.exe -s "+args).c_str(),
            NULL, NULL,
            TRUE, 0,
            NULL, NULL,
            &si, &pi);

      // Now that handles have been inherited, close it to be safe.
      // You don't want to read or write to them accidentally.
      CloseHandle(hPipeOutputWrite);
      CloseHandle(hPipeInputRead);
 
      // Now test to capture DOS application output by reading
      // hPipeOutputRead.  Could also write to DOS application
      // standard input by writing to hPipeInputWrite.

      while(TRUE)
      {
         bTest=ReadFile(
            hPipeOutputRead,      // handle of the read end of our pipe
            &szBuffer,            // address of buffer that receives data
            256,                  // number of bytes to read
            &dwNumberOfBytesRead, // address of number of bytes read
            NULL                  // non-overlapped.
            );
 
        if (!bTest){
            //wsprintf(szMsg, "Error #%d reading pipe.",GetLastError());
            //MessageBox(NULL, szMsg, "Test", MB_OK);
            break;
        }
 
        // do something with data.
        szBuffer[dwNumberOfBytesRead] = 0;  // null terminate
        //MessageBox(NULL, szBuffer, "Test", MB_OK);
        ret+=szBuffer;
      }
 
      // Wait for CONSPAWN to finish.
      WaitForSingleObject (pi.hProcess, INFINITE);
 
      // Close all remaining handles
      CloseHandle (pi.hProcess);
      CloseHandle (hPipeOutputRead);
      CloseHandle (hPipeInputWrite);
      return ret;
}
//---------------------------------------------------------------------------
String nslookup(String domain)
{
      String ret;
      SECURITY_ATTRIBUTES sa          = {0};
      STARTUPINFO         si          = {0};
      PROCESS_INFORMATION pi          = {0};
      HANDLE              hPipeOutputRead  = NULL;
      HANDLE              hPipeOutputWrite = NULL;
      BOOL                bTest = 0;
      DWORD               dwNumberOfBytesRead = 0;
      CHAR                szMsg[100];
      CHAR                szBuffer[256];

      sa.nLength = sizeof(sa);
      sa.bInheritHandle = TRUE;
      sa.lpSecurityDescriptor = NULL;


      // Create pipe for standard output redirection.
      CreatePipe(&hPipeOutputRead,  // read handle
              &hPipeOutputWrite, // write handle
              &sa,      // security attributes
              0      // number of bytes reserved for pipe - 0 default
              );

      // Make child process use hPipeOutputWrite as standard out,
      // and make sure it does not show on screen.
      si.cb = sizeof(si);
      si.dwFlags     = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
      si.wShowWindow = SW_HIDE;
      si.hStdInput   = NULL;
      si.hStdOutput  = hPipeOutputWrite;
      si.hStdError   = hPipeOutputWrite;
 
      CreateProcess (
            NULL, ("nslookup.exe "+domain).c_str(),
            NULL, NULL,
            TRUE, 0,
            NULL, NULL,
            &si, &pi);

      // Now that handles have been inherited, close it to be safe.
      // You don't want to read or write to them accidentally.
      CloseHandle(hPipeOutputWrite);

 
      // Now test to capture DOS application output by reading
      // hPipeOutputRead.  Could also write to DOS application
      // standard input by writing to hPipeInputWrite.

      while(TRUE)
      {
         bTest=ReadFile(
            hPipeOutputRead,      // handle of the read end of our pipe
            &szBuffer,            // address of buffer that receives data
            256,                  // number of bytes to read
            &dwNumberOfBytesRead, // address of number of bytes read
            NULL                  // non-overlapped.
            );
 
        if (!bTest){
            //wsprintf(szMsg, "Error #%d reading pipe.",GetLastError());
            //MessageBox(NULL, szMsg, "Test", MB_OK);
            break;
        }
 
        // do something with data.
        szBuffer[dwNumberOfBytesRead] = 0;  // null terminate
        //MessageBox(NULL, szBuffer, "Test", MB_OK);
        ret+=szBuffer;
      }
 
      // Wait for CONSPAWN to finish.
      WaitForSingleObject (pi.hProcess, INFINITE);
 
      // Close all remaining handles
      CloseHandle (pi.hProcess);
      CloseHandle (hPipeOutputRead);
      TStringList *ss=new TStringList;
      TStringList *addr=new TStringList;
      ss->Text=ret;
      for(int i=0;i<ss->Count;i++)
        {
           if(ss->Strings[i].Pos("名称:") || ss->Strings[i].Pos("Name:"))
             {
                for(int j=i;j<ss->Count;j++)
                  if(ss->Strings[j].Pos("Address:") || ss->Strings[j].Pos("Addresses:"))
                     {
                        addr->Delimiter=' '; addr->DelimitedText=ss->Strings[j];
                        if(addr->Count>=2 && addr->Strings[0].Pos("Address"))
                           {
                               ret=addr->Strings[1];
                               delete addr;
                               delete ss;
                               return ret;
                           }
                     }
             }
        }
      delete addr;
      delete ss;
      return "";
}
//---------------------------------------------------------------------------------

__fastcall TForm1::TForm1(TComponent* Owner)
    : TForm(Owner)
{
}
//---------------------------------------------------------------------------
String TForm1::Timestamp()
{

  SYSTEMTIME st;
  GetSystemTime(&st);
  String timestamp;
  timestamp.printf("%04d-%02d-%02dT%02d%%3A%02d%%3A%02dZ",st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond);
  //String ts=FormatDateTime("yyyy-mm-dd'T'hh%3Ann%3Ass'Z'",Now());
  return timestamp;

}
//---------------------------------------------------------------------------
String TForm1::get_current_ip(String host)
{

return nslookup(host+" 223.5.5.5");
//	 网络初始化
//    WSADATA wsaData;
//    WSAStartup(MAKEWORD(1,1), &wsaData);
//
//	 度娘来了
//	char *szWeb = host.c_str();
//    HOSTENT *pHost = gethostbyname(szWeb);
//
//	 打印度娘的ip地址(实际上， 这个地址经常变动， 所以如果你得到的地址不一致， 那也是正常的)
//	if(NULL != pHost)
//	{
//		const char* pIPAddr = inet_ntoa(*((struct in_addr *)pHost->h_addr)) ;
//		printf("web server ip is : %s\n", pIPAddr);
//        return pIPAddr;
//	}
//
//	return "";
}
//---------------------------------------------------------------------------
String TForm1::get_ip()
{
  return curl("http://whatismyip.akamai.com/");
}

String TForm1::urlencode(String url)
{
   int urllen=url.Length();
   String rurl="";
   String temp="" ;
   char *urldata=url.c_str();
   for (int i=0;i<urllen;i++)
     {
       if((urldata[i]>='a' && urldata[i]<='z') || (urldata[i]>='A' && urldata[i]<='Z') || (urldata[i]>='0' && urldata[i]<='9') || urldata[i]=='.' ||  urldata[i]=='_' || urldata[i]=='-')
          {
             rurl+=urldata[i];
          }
       else
          {
             temp.printf("%%%02X",urldata[i]);
             rurl+=temp;
          }

     }
   return rurl;
}

String TForm1::send_request(String Action,String ParamStr)
{
    String  args="AccessKeyId=" + aliddns_ak + "&Action=" + Action + "&Format=json&" + ParamStr + "&Version=2015-01-09";
    String encodeargs="GET&%2F&"+urlencode(args);
    CHMAC_SHA1 hmac_sha;
    String sk=aliddns_sk+"&";
    String hash=hmac_sha.Base64HMAC_SHA1(encodeargs.c_str(),encodeargs.Length(),sk.c_str(),sk.Length());
//    String hash1=openssl("dgst -sha1 -hmac "+aliddns_sk+" -binary",encodeargs);
//    String hash2=openssl("base64",hash1);
    String rulhash=urlencode(hash);
    //curl "http://alidns.aliyuncs.com/?$args&Signature=$hash" 2> /dev/null
    String url="http://alidns.aliyuncs.com/?" + args + "&Signature=" + rulhash;
    String ret=curl(url);
    return  ret;
}







String TForm1::query_recordid()
{
  String args="SignatureMethod=HMAC-SHA1&SignatureNonce=" + Timestamp( )+ "&SignatureVersion=1.0&SubDomain="+ aliddns_name+ "." +aliddns_domain+ "&Timestamp="+Timestamp();
   return send_request("DescribeSubDomainRecords",args);
}

String TForm1::update_record()
{
    String args="RR="+ aliddns_name + "&RecordId="+ aliddns_record_id +"&SignatureMethod=HMAC-SHA1&SignatureNonce=" +Timestamp()+ "&SignatureVersion=1.0&Timestamp="+Timestamp()+"&Type=A&Value="+ip;
    return send_request("UpdateDomainRecord",args);
}

String TForm1::add_record()
{
    String args="RR="+ aliddns_name + "&SignatureMethod=HMAC-SHA1&SignatureNonce=" +Timestamp()+ "&SignatureVersion=1.0&Timestamp="+Timestamp()+"&Type=A&Value="+ip;
    return send_request("AddDomainRecord&DomainName=" +aliddns_domain,args);
}

String TForm1::get_recordid(String retstr)
{


   String idtemp=retstr;
   int p=idtemp.Pos("\"RecordId\":");
   if(p>0)
   {
   idtemp=idtemp.SubString(p+12,idtemp.Length()-p-10);
   int p1=idtemp.Pos("\",");
   idtemp=idtemp.SubString(1,p1-1);
   return idtemp;
   }
   return "";

}


void TForm1::loadconfig()
{
    TIniFile *ini=new TIniFile(ExtractFileDir(ParamStr(0))+"\\aliddns.ini");
    aliddns_ak=ini->ReadString("base","app_key",edt1->Text);
    aliddns_sk=ini->ReadString("base","app_secret",edt2->Text);
    aliddns_domain=ini->ReadString("base","main_domain",edt3->Text);
    aliddns_name=ini->ReadString("base","sub_domain",edt4->Text);
    aliddns_enable=ini->ReadBool("base","enable",chk1->Checked);
    aliddns_record_id=ini->ReadString("base","record_id","");
    time=ini->ReadInteger("base","time",tmr1->Interval/60000);
    startmini=ini->ReadBool("base","startmini",chk2->Checked);
    delete ini;

    chk1->Checked=aliddns_enable;
    edt1->Text=aliddns_ak;
    edt2->Text=aliddns_sk;
    edt3->Text=aliddns_domain;
    edt4->Text=aliddns_name;
    tmr1->Interval=time*60000;
    tmr1->Enabled=aliddns_enable;
    chk2->Checked=startmini;
    if(aliddns_enable)
      {
        if(check_aliddns())
          go_record(); 
      }


}
void TForm1::saveconfig()
{

    aliddns_enable=chk1->Checked;
    aliddns_ak=edt1->Text;
    aliddns_sk=edt2->Text;
    aliddns_domain=edt3->Text;
    aliddns_name=edt4->Text;
    time=edt5->Text.ToInt();
    aliddns_record_id="";
    startmini=chk2->Checked;


    TIniFile *ini=new TIniFile(ExtractFileDir(ParamStr(0))+"\\aliddns.ini");
    ini->WriteString("base","app_key",aliddns_ak);
    ini->WriteString("base","app_secret",aliddns_sk);
    ini->WriteString("base","main_domain",aliddns_domain);
    ini->WriteString("base","sub_domain",aliddns_name);
    ini->WriteBool("base","enable",aliddns_enable);
    ini->WriteString("base","record_id","");
    ini->WriteInteger("base","time",time);
    ini->WriteBool("base","startmini",startmini);

    delete ini;

}
//----------------------------------------------------------------------------
void TForm1::savelog(String Msg)
{
    int fh;
    if(!FileExists(ExtractFileDir(ParamStr(0))+"\\aliddns.log"))
        fh=FileCreate(ExtractFileDir(ParamStr(0))+"\\aliddns.log");
    else
        fh=FileOpen(ExtractFileDir(ParamStr(0))+"\\aliddns.log",fmOpenReadWrite);
    if(fh!=-1)
        {
            FileSeek(fh,0,2);
            String log= FormatDateTime("yyyy-mm-dd hh:nn:ss ",Now())+Msg+"\r\n";
            FileWrite(fh,log.c_str(),log.Length());
            FileClose(fh);
        }

}

//----------------------------------------------------------------------------
bool TForm1::check_aliddns()
{
    String ip=get_ip();
    String current_ip=get_current_ip(Form1->aliddns_name+"."+Form1->aliddns_domain);
    savelog("当前路由IP:"+ip);
    savelog("远程解析IP:"+current_ip);
    if(ip==current_ip)
      {
         savelog("IP未改变，无需更新.");
         return false;
      }
    else
      {
         Form1->ip=ip;
         savelog("更新中...");
         return true;
      }
}

bool TForm1::go_record()
{
  if(aliddns_record_id=="")
      {
         aliddns_record_id=get_recordid(query_recordid());
         if(aliddns_record_id=="")
           {
             aliddns_record_id=get_recordid(add_record());
             savelog("添加 record "+aliddns_record_id);
           }
         else
           {
             update_record();
             savelog("更新 record "+aliddns_record_id);
           }


      }
  if(aliddns_record_id=="")
      {
             savelog("更新出错,请检查设置！");
      }
  else
      {
          savelog("更新成功！IP:"+ip);
          TIniFile *ini=new TIniFile(ExtractFileDir(ParamStr(0))+"\\aliddns.ini");
          ini->WriteString("base","record_id",aliddns_record_id);
          delete ini;
          return true;
      }
  return false;

}
void __fastcall TForm1::edt5Change(TObject *Sender)
{
  int &n=10;
if(!TryStrToInt(edt5->Text,n))
    edt5->Text=time;
}
//---------------------------------------------------------------------------

void __fastcall TForm1::tmr2Timer(TObject *Sender)
{

tmr2->Enabled=false;
loadconfig();
if(startmini) trayIcon2->Minimize();


}
//---------------------------------------------------------------------------

void __fastcall TForm1::btn3Click(TObject *Sender)
{
   if(check_aliddns())
       go_record();
}
//---------------------------------------------------------------------------

void __fastcall TForm1::btn1Click(TObject *Sender)
{
saveconfig();
if(aliddns_enable)
  {
     tmr1->Interval=time*60000;
     tmr1->Enabled=true;
     if(check_aliddns())
        go_record();
  }
else
  {
     tmr1->Enabled=false;
  }
}
//---------------------------------------------------------------------------

void __fastcall TForm1::tmr1Timer(TObject *Sender)
{
     if(check_aliddns())
        go_record();    
}
//---------------------------------------------------------------------------

void __fastcall TForm1::btn2Click(TObject *Sender)
{
WinExec(String("Notepad.exe "+ExtractFileDir(ParamStr(0))+"\\aliddns.log").c_str(),SW_NORMAL);
}
//---------------------------------------------------------------------------

void __fastcall TForm1::btn4Click(TObject *Sender)
{
String ipaddr=nslookup(edt4->Text+"."+edt3->Text);
  MessageBoxA(NULL,(edt4->Text+"."+edt3->Text+"\n"+ipaddr).c_str(),"nslookup",MB_OK);
}
//---------------------------------------------------------------------------

