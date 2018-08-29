object Form1: TForm1
  Left = 206
  Top = 197
  Width = 587
  Height = 347
  Caption = 'FilterDriverCommunicater'
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  OldCreateOrder = False
  Position = poScreenCenter
  PixelsPerInch = 96
  TextHeight = 13
  object Panel1: TPanel
    Left = 0
    Top = 275
    Width = 579
    Height = 41
    Align = alBottom
    TabOrder = 0
    object btSend: TButton
      Left = 292
      Top = 8
      Width = 75
      Height = 25
      Caption = 'send'
      TabOrder = 0
    end
    object txtSend: TEdit
      Left = 2
      Top = 8
      Width = 289
      Height = 21
      TabOrder = 1
      Text = 'txtSend'
    end
    object txtPortName: TEdit
      Left = 373
      Top = 10
      Width = 88
      Height = 21
      TabOrder = 2
      Text = '\FilterPort'
    end
    object btSetFilterPort: TButton
      Left = 460
      Top = 8
      Width = 85
      Height = 25
      Caption = 'set'
      TabOrder = 3
      OnClick = btSetFilterPortClick
    end
  end
  object Panel2: TPanel
    Left = 0
    Top = 0
    Width = 579
    Height = 275
    Align = alClient
    Caption = 'Panel2'
    TabOrder = 1
    object txtRecv: TMemo
      Left = 1
      Top = 1
      Width = 577
      Height = 273
      Align = alClient
      ScrollBars = ssBoth
      TabOrder = 0
      OnClick = txtRecvClick
    end
    object Button1: TButton
      Left = 288
      Top = 184
      Width = 75
      Height = 25
      Caption = 'Test'
      TabOrder = 1
      OnClick = Button1Click
    end
    object Edit1: TEdit
      Left = 232
      Top = 157
      Width = 121
      Height = 21
      TabOrder = 2
    end
  end
end
