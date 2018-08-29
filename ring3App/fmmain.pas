unit fmmain;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, ExtCtrls;

type
  Ttrd=class(TThread)
  public
    procedure execute;override;
  end;

  TForm1 = class(TForm)
    Panel1: TPanel;
    Panel2: TPanel;
    txtRecv: TMemo;
    btSend: TButton;
    txtSend: TEdit;
    txtPortName: TEdit;
    btSetFilterPort: TButton;
    Button1: TButton;
    Edit1: TEdit;
    procedure btSetFilterPortClick(Sender: TObject);
    procedure txtRecvClick(Sender: TObject);
    procedure Button1Click(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

  THREAD_CONTEXT=record
    hPort:THandle;
    completion:THandle;
  end;
  PTHREAD_CONTEXT=^THREAD_CONTEXT;

  SECURITY_ATTRIBUTES=record
    nLength:DWORD;
    lpSecurityDescriptor:Pointer;
    bInheritHandle:BOOL;
  end;
  LPSECURITY_ATTRIBUTES=^SECURITY_ATTRIBUTES;

  FILTER_MESSAGE_HEADER=record
    ReplyLength:ULONG;
    MessageId:int64;
  end;
  PFILTER_MESSAGE_HEADER=^FILTER_MESSAGE_HEADER;

  KERNEL_MESSAGE=record
    MessageHeader:FILTER_MESSAGE_HEADER;
    messages:array[0..1023] of char;
    Ovlp:OVERLAPPED;
  end;
  PKERNEL_MESSAGE=^KERNEL_MESSAGE;

function FilterConnectCommunicationPort (
    lpPortName:PWideChar;
    dwOptions:DWORD;
    lpContext:Pointer;
    wSizeOfContext:Word;
    lpSecurityAttributes:LPSECURITY_ATTRIBUTES;
    var hPort:THandle
    ):Cardinal;stdcall;external 'FltLib.dll' name 'FilterConnectCommunicationPort';
    
function FilterGetMessage (
    hPort:THandle;
    lpMessageBuffer:pFILTER_MESSAGE_HEADER;
    dwMessageBufferSize:DWORD;
    lpOverlapped:pOVERLAPPED
    ):integer;stdcall;external 'FltLib.dll' name 'FilterGetMessage';

const
  GENERIC_READ=$80000000;
  GENERIC_WRITE=$40000000;
  GENERIC_EXECUTE=$20000000;
  GENERIC_ALL=$10000000;

  OPEN_EXISTING=3;
  FILE_ATTRIBUTE_NORMAL=$00000080;

  PATH_KERNEL_DRIVER ='\\.\zer0m0n';
  IOCTL_PROC_MALWARE =$222000;
  IOCTL_PROC_TO_HIDE =$222004;
  IOCTL_CUCKOO_PATH  =$222008;

var
  Form1: TForm1;

implementation

var
  context:THREAD_CONTEXT;

{$R *.dfm}

procedure TForm1.btSetFilterPortClick(Sender: TObject);
begin
  FilterConnectCommunicationPort(pwidechar(widestring(txtportname.Text)),0,nil,0,nil,context.hPort);
  //ShowMessage(inttostr(context.hPort));
  Ttrd.Create(False);
  //CreateIoCompletionPort()
end;

procedure TForm1.Button1Click(Sender: TObject);
var
  b:boolean;
  h:THandle;
  pid:Cardinal;
  hDevice:THandle;
  s_pid:pchar;
  dwBytesReturned:UINT;
begin
  pid:=StrToInt(Edit1.Text);  //GetCurrentProcessId();
  s_pid:=PChar(Edit1.Text);
  hDevice := CreateFile(PATH_KERNEL_DRIVER, GENERIC_READ or GENERIC_WRITE, 0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
  b:=DeviceIoControl(hDevice, IOCTL_PROC_MALWARE, s_pid, strlen(s_pid), nil, 0, dwBytesReturned, nil);
  //b:=DebugActiveProcess(pid);
  txtRecv.Lines.Text:=IntToStr(strlen(s_pid))+'&'+BoolToStr(b);
end;

procedure TForm1.txtRecvClick(Sender: TObject);
begin

end;

{ Ttrd }

procedure Ttrd.execute;
var
  msg1:pKERNEL_MESSAGE;
  hr:integer;
  i:integer;
begin
  inherited;
  msg1:=AllocMem(SizeOf(KERNEL_MESSAGE));
  while True do
  begin
    FillMemory(@(msg1.Ovlp),SizeOf(OVERLAPPED),0);
    hr:=FilterGetMessage(context.hPort,@(msg1.MessageHeader),SizeOf(KERNEL_MESSAGE),nil);
    i:=NativeUInt(@(pKERNEL_MESSAGE(0).Ovlp));
    //msg1:=Pointer(NativeUInt(msg1)-i);
    if msg1.messages='' then continue;
    i:=0;
    while msg1.messages[i]<> #$0a do
      inc(i);
    msg1.messages[i]:=#0;
    if msg1.messages='' then Continue;
    Form1.txtRecv.Lines.Add(strpas(msg1.messages));
  end;
end;

end.
