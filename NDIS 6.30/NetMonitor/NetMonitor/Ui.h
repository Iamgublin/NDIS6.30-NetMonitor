#pragma once
#define MAX_LOADSTRING 100
using namespace std;
// 全局变量:
extern int Cxrect;                                     //当前窗口X轴大小
extern int Cyrect;									   //当前窗口Y轴大小
extern HWND HwndWinMain;							   //主窗口句柄
extern HWND ListView, StatusBar, StaticWindow;		   //List，状态栏，静态窗口控件句柄	
extern HINSTANCE hInst;                                // 当前实例
extern TCHAR szTitle[MAX_LOADSTRING];                  // 标题栏文本
extern TCHAR szWindowClass[MAX_LOADSTRING];            // 主窗口类名
extern HANDLE FilterHandle;							   //底层过滤器句柄

