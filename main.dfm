object Form1: TForm1
  Left = 940
  Top = 302
  BorderIcons = [biSystemMenu, biMinimize]
  BorderStyle = bsSingle
  Caption = #38463#37324'DDNS - waterun'
  ClientHeight = 297
  ClientWidth = 342
  Color = clBtnFace
  Font.Charset = ANSI_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = #24494#36719#38597#40657
  Font.Style = []
  OldCreateOrder = False
  Position = poDesktopCenter
  PixelsPerInch = 96
  TextHeight = 17
  object lbl1: TLabel
    Left = 80
    Top = 56
    Width = 48
    Height = 17
    Caption = 'APP KEY'
  end
  object lbl2: TLabel
    Left = 58
    Top = 88
    Width = 70
    Height = 17
    Caption = 'APP SECRET'
  end
  object lbl3: TLabel
    Left = 92
    Top = 120
    Width = 36
    Height = 17
    Caption = #20027#22495#21517
  end
  object lbl4: TLabel
    Left = 92
    Top = 152
    Width = 36
    Height = 17
    Caption = #23376#22495#21517
  end
  object lbl5: TLabel
    Left = 48
    Top = 184
    Width = 80
    Height = 17
    Caption = #26816#26597#26102#38388'('#20998#38047')'
  end
  object lbl6: TLabel
    Left = 32
    Top = 272
    Width = 283
    Height = 17
    Caption = 'OPENWRT'#36719#36335#30001'-'#22266#20214'-'#35831#20851#27880#30707#20687#39740#32676#65306'24946530'
  end
  object lbl7: TLabel
    Left = 32
    Top = 256
    Width = 106
    Height = 17
    Caption = #29256#26435#27809#26377#65306'waterun'
  end
  object btn1: TButton
    Left = 232
    Top = 224
    Width = 75
    Height = 25
    Caption = #20445#23384'&&'#24212#29992
    TabOrder = 0
    OnClick = btn1Click
  end
  object chk1: TCheckBox
    Left = 48
    Top = 24
    Width = 137
    Height = 17
    Caption = #24320#21551'aliddns'#21160#24577#22495#21517
    TabOrder = 1
  end
  object edt1: TEdit
    Left = 136
    Top = 52
    Width = 121
    Height = 26
    TabOrder = 2
    Text = 'LTAIntF3xPDi3MSL'
  end
  object edt2: TEdit
    Left = 136
    Top = 84
    Width = 121
    Height = 26
    PasswordChar = '*'
    TabOrder = 3
    Text = 'CzIKEDXwvcKxtSwu27VuC4kaJbEApc'
  end
  object edt3: TEdit
    Left = 136
    Top = 116
    Width = 121
    Height = 26
    TabOrder = 4
    Text = 'lean.tv'
  end
  object edt4: TEdit
    Left = 136
    Top = 148
    Width = 121
    Height = 26
    TabOrder = 5
    Text = 'show'
  end
  object edt5: TEdit
    Left = 136
    Top = 180
    Width = 121
    Height = 26
    TabOrder = 6
    Text = '10'
    OnChange = edt5Change
  end
  object btn2: TButton
    Left = 40
    Top = 224
    Width = 75
    Height = 25
    Caption = #26597#30475#35760#24405
    TabOrder = 7
    OnClick = btn2Click
  end
  object btn3: TButton
    Left = 136
    Top = 224
    Width = 75
    Height = 25
    Caption = #25163#21160#26356#26032
    TabOrder = 8
    OnClick = btn3Click
  end
  object chk2: TCheckBox
    Left = 200
    Top = 24
    Width = 129
    Height = 17
    Caption = #21551#21160#21518#26368#23567#21270#21040#25176#30424
    TabOrder = 9
  end
  object btn4: TButton
    Left = 264
    Top = 149
    Width = 25
    Height = 25
    Caption = '?'
    TabOrder = 10
    OnClick = btn4Click
  end
  object tmr1: TTimer
    Enabled = False
    Interval = 60000
    OnTimer = tmr1Timer
    Left = 264
    Top = 176
  end
  object tmr2: TTimer
    Interval = 100
    OnTimer = tmr2Timer
    Left = 24
    Top = 8
  end
  object trayIcon2: TTrayIcon
    Visible = True
    Hide = True
    RestoreOn = imDoubleClick
    PopupMenuOn = imNone
    Left = 24
    Top = 64
  end
end
