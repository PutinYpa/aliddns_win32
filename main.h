//---------------------------------------------------------------------------

#ifndef mainH
#define mainH
//---------------------------------------------------------------------------
#include <Classes.hpp>
#include <Controls.hpp>
#include <StdCtrls.hpp>
#include <Forms.hpp>
#include <ExtCtrls.hpp>
#include "trayicon.h"
//---------------------------------------------------------------------------
class TForm1 : public TForm
{
__published:	// IDE-managed Components
    TButton *btn1;
    TCheckBox *chk1;
    TLabel *lbl1;
    TLabel *lbl2;
    TLabel *lbl3;
    TLabel *lbl4;
    TLabel *lbl5;
    TEdit *edt1;
    TEdit *edt2;
    TEdit *edt3;
    TEdit *edt4;
    TEdit *edt5;
    TButton *btn2;
    TButton *btn3;
    TTimer *tmr1;
    TTimer *tmr2;
    TTrayIcon *trayIcon2;
    TCheckBox *chk2;
    TLabel *lbl6;
    TLabel *lbl7;
    TButton *btn4;
    void __fastcall edt5Change(TObject *Sender);
    void __fastcall tmr2Timer(TObject *Sender);
    void __fastcall btn3Click(TObject *Sender);
    void __fastcall btn1Click(TObject *Sender);
    void __fastcall tmr1Timer(TObject *Sender);
    void __fastcall btn2Click(TObject *Sender);
    void __fastcall btn4Click(TObject *Sender);
private:	// User declarations
    AnsiString Timestamp();
    String get_current_ip(String host);
    String get_ip();
    String urlencode(String  url);
    String send_request(String Action,String ParamStr);
    String get_recordid(String retstr);
    String query_recordid();
    String update_record();
    String add_record();
    void savelog(String Msg);
    bool check_aliddns();
    bool go_record();


public:		// User declarations
    __fastcall TForm1(TComponent* Owner);
    bool aliddns_enable;
    String aliddns_ak;
    String aliddns_sk;
    String aliddns_record_id;
    String aliddns_domain;
    String aliddns_name;
    String DATE;
    String timestamp;
    String ip;
    int time;
    bool startmini;
    void loadconfig();
    void saveconfig();
    void aplyconfig();

};
//---------------------------------------------------------------------------
extern PACKAGE TForm1 *Form1;
//---------------------------------------------------------------------------
#endif
